//! Exact terminal cleanup under the retained caller's lifetime authority.
//! This module does not grant closure, recover an app or choose live exchanges.
use super::*;
use rustix::fs::unlinkat;

/// Core filesystem engine. Production callers supply either the SAME checked
/// TerminalBoundary or the retained FencedAppRecovery through typed boundaries.
pub(super) fn run(store: &Store) -> Result<()> {
    #[cfg(test)]
    let _elapsed = diagnostics::Elapsed::start("settlement.total", None);
    let record = store.record()?;
    if !matches!(record.phase, AppPhase::Committed | AppPhase::RolledBack) {
        return Err(SlotError::Invalid);
    }
    store.layout(&record)?;
    let Some(directories) = Directories::existing(store)? else {
        if store.record()? != record {
            return Err(SlotError::Invalid);
        }
        return Ok(());
    };
    let mut plan = settle_publication(store, &directories)?;
    let record = bound_record(store, &plan)?;
    let cleanup = if record.phase == AppPhase::Committed {
        SupportPhase::CleanupNew
    } else if record.phase == AppPhase::RolledBack {
        SupportPhase::CleanupOld
    } else {
        return Err(SlotError::Invalid);
    };
    let layout = inspect_layout(&directories, store, &plan)?;
    let mut desired = plan.clone();
    desired.phase = cleanup;
    desired.check_layout(record.phase, &layout)?;
    match plan.phase {
        SupportPhase::Ready => plan.check_layout(record.phase, &layout)?,
        SupportPhase::Staging if cleanup == SupportPhase::CleanupOld => {
            // A recognized abort may already have missing anonymous successors.
            // No missing member is accepted from Ready before cleanup is durable.
            plan.check_layout(AppPhase::Prepared, &layout)?;
        }
        phase if phase == cleanup => {}
        _ => return Err(SlotError::Invalid),
    }
    if plan.phase != cleanup {
        publish_plan(&directories, store, &desired, Some(&plan))?;
        plan = desired;
    }
    support_operation!(
        "settlement.cleanup",
        None,
        cleanup_members(store, &directories, &plan)
    )
}

/// Only an exact same-context phase edge may finish a known plan-next rename.
/// Unknown/torn alternatives never replace the canonical record or get removed.
pub(super) fn settle_publication(store: &Store, directories: &Directories) -> Result<Plan> {
    directories.check(store)?;
    let names = inventory(&directories.support)?;
    if names & (1 << COUNT) == 0 {
        return Err(SlotError::Invalid);
    }
    let plan = load_plan(directories, store, PLAN)?;
    let record = bound_record(store, &plan)?;
    if names & (1 << (COUNT + 1)) == 0 {
        return Ok(plan);
    }
    let next = load_plan(directories, store, NEXT)?;
    let mut expected = plan.clone();
    expected.phase = next.phase;
    if next != expected {
        return Err(SlotError::Invalid);
    }
    let layout = inspect_members(directories, store, &plan, names)?;
    match (plan.phase, next.phase, record.phase) {
        (SupportPhase::Staging, SupportPhase::Ready, AppPhase::Prepared) => {
            plan.check_layout(record.phase, &layout)?;
            next.check_layout(record.phase, &layout)?;
        }
        (SupportPhase::Staging, SupportPhase::CleanupOld, AppPhase::RolledBack) => {
            plan.check_layout(AppPhase::Prepared, &layout)?;
            next.check_layout(record.phase, &layout)?;
        }
        (SupportPhase::Ready, SupportPhase::CleanupOld, AppPhase::RolledBack)
        | (SupportPhase::Ready, SupportPhase::CleanupNew, AppPhase::Committed) => {
            plan.check_layout(record.phase, &layout)?;
            next.check_layout(record.phase, &layout)?;
        }
        _ => return Err(SlotError::Invalid),
    }
    directories.check(store)?;
    if bound_record(store, &plan)? != record
        || load_plan(directories, store, PLAN)? != plan
        || load_plan(directories, store, NEXT)? != next
    {
        return Err(SlotError::Invalid);
    }
    let result = renameat(&directories.support, NEXT, &directories.support, PLAN);
    if let Err(error) = result {
        // The returned error is not evidence that rename did not happen.
        inventory(&directories.support)?;
        return Err(error.into());
    }
    point("settlement-next-renamed")?;
    directories.support.sync_all()?;
    point("settlement-next-synced")?;
    if load_plan(directories, store, PLAN)? != next
        || inventory(&directories.support)? & (1 << (COUNT + 1)) != 0
    {
        return Err(SlotError::Invalid);
    }
    Ok(next)
}

fn cleanup_members(store: &Store, directories: &Directories, plan: &Plan) -> Result<()> {
    #[cfg(test)]
    let _elapsed = diagnostics::Elapsed::start("cleanup.total", None);
    let record = bound_record(store, plan)?;
    let missing = match (plan.phase, record.phase) {
        (SupportPhase::CleanupOld, AppPhase::RolledBack) => Placement::OldMissing,
        (SupportPhase::CleanupNew, AppPhase::Committed) => Placement::NewMissing,
        _ => return Err(SlotError::Invalid),
    };
    directories.check(store)?;
    if load_plan(directories, store, PLAN)? != *plan {
        return Err(SlotError::Invalid);
    }
    plan.check_layout(record.phase, &inspect_layout(directories, store, plan)?)?;
    for index in 0..COUNT {
        #[cfg(test)]
        let _elapsed = diagnostics::Elapsed::start("cleanup.member-total", Some(index));
        directories.check(store)?;
        if bound_record(store, plan)? != record || load_plan(directories, store, PLAN)? != *plan {
            return Err(SlotError::Invalid);
        }
        let names = inventory(&directories.support)?;
        if names & (1 << (COUNT + 1)) != 0 || names & (1 << COUNT) == 0 {
            return Err(SlotError::Invalid);
        }
        let placement = inspect_pair(directories, store, plan, index, names)?;
        let mut single = [missing; COUNT];
        single[index] = placement;
        plan.check_layout(record.phase, &single)?;
        if placement != missing {
            let result = unlinkat(&directories.support, NAMES[index], AtFlags::empty());
            if let Err(error) = result {
                inspect_layout(directories, store, plan)?;
                return Err(error.into());
            }
            #[cfg(test)]
            point(&format!("cleanup-member-unlinked-{index}"))?;
            if inspect_pair(
                directories,
                store,
                plan,
                index,
                inventory(&directories.support)?,
            )? != missing
            {
                return Err(SlotError::Invalid);
            }
        }
        // Retry of an already missing recorded inactive inode still needs sync.
        support_operation!(
            "cleanup.member-sync",
            Some(index),
            directories.support.sync_all()
        )?;
        #[cfg(test)]
        point(&format!("cleanup-member-synced-{index}"))?;
    }
    directories.check(store)?;
    if bound_record(store, plan)? != record
        || load_plan(directories, store, PLAN)? != *plan
        || inspect_layout(directories, store, plan)? != [missing; COUNT]
        || inventory(&directories.support)? != 1 << COUNT
    {
        return Err(SlotError::Invalid);
    }
    support_operation!(
        "cleanup.plan-boundary-sync",
        None,
        directories.support.sync_all()
    )?;
    unlinkat(&directories.support, PLAN, AtFlags::empty())?;
    point("cleanup-plan-unlinked")?;
    support_operation!("cleanup.empty-sync", None, directories.support.sync_all())?;
    point("cleanup-empty-synced")?;
    directories.check(store)?;
    if inventory(&directories.support)? != 0 || store.record()? != record {
        return Err(SlotError::Invalid);
    }
    Ok(())
}

#[cfg(test)]
#[path = "app_slot_support_settle_tests.rs"]
mod tests;

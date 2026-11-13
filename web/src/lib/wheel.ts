// One wheel notch per event in the direction of the delta. Browsers report
// fractional deltas for trackpads and high-resolution wheels; the old check
// floored the delta, so a small positive one became 0 and was dropped while
// the same negative one became -1 and scrolled. Zero means no movement.
export function wheelStep(deltaY: number, scrollDirection: number): number {
  if (!Number.isFinite(deltaY) || deltaY === 0) {
    return 0;
  }
  return (deltaY > 0 ? 1 : -1) * scrollDirection;
}

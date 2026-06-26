import { useEffect, useState } from 'react';
import { message, Switch } from 'antd';

import * as backendApi from '@/api/backend.ts';
import * as scriptApi from '@/api/script.ts';

const SWITCH_TO_RUST_SCRIPT = 'switch-backend-rust.sh';
const SWITCH_TO_GO_SCRIPT = 'switch-backend-go.sh';

export const BackendSwitch = () => {
  const [enabled, setEnabled] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    getBackend();
  }, []);

  function getBackend() {
    setIsLoading(true);

    backendApi
      .getHealth()
      .then((rsp) => {
        setEnabled(rsp.data?.backend === 'rust');
      })
      .catch(() => {
        setEnabled(false);
      })
      .finally(() => {
        setIsLoading(false);
      });
  }

  function reloadAfterSwitch() {
    window.setTimeout(() => {
      window.location.reload();
    }, 3500);
  }

  function update(checked: boolean) {
    if (isLoading) return;
    setIsLoading(true);

    const script = checked ? SWITCH_TO_RUST_SCRIPT : SWITCH_TO_GO_SCRIPT;

    scriptApi
      .runScript(script, 'background')
      .then((rsp) => {
        if (rsp.code !== 0) {
          throw new Error(rsp.msg || 'Backend switch failed');
        }

        setEnabled(checked);
        message.loading('Switching backend...', 3);
        reloadAfterSwitch();
      })
      .catch((err) => {
        console.log(err);
        message.error('Failed to switch backend');
        setIsLoading(false);
      });
  }

  return (
    <div className="flex items-center justify-between">
      <div className="flex flex-col space-y-1">
        <span>Enable Hardened Backend</span>
        <span className="text-xs text-neutral-500">
          Switch between Rust Hardened and Go backend
        </span>
      </div>

      <Switch checked={enabled} loading={isLoading} onChange={update} />
    </div>
  );
};

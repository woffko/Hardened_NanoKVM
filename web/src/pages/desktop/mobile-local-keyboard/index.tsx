import { ClipboardEvent, FormEvent, KeyboardEvent, useEffect, useRef } from 'react';
import { message } from 'antd';
import { useAtom, useSetAtom } from 'jotai';

import { paste } from '@/api/hid.ts';
import { CompositionGate } from '@/lib/composition.ts';
import { KeyboardReport } from '@/lib/keyboard.ts';
import * as storage from '@/lib/localstorage.ts';
import { client, MessageEvent } from '@/lib/websocket.ts';
import { isKeyboardEnableAtom, isLocalKeyboardOpenAtom } from '@/jotai/keyboard.ts';

const INPUT_ID = 'nanokvm-mobile-local-keyboard';
const VALID_PASTE_LANGUAGES = new Set(['en', 'de', 'fr', 'ru', 'ko', 'ja']);

function getPasteLanguage() {
  const language = storage.getKeyboardLanguage() || 'en';
  return VALID_PASTE_LANGUAGES.has(language) ? language : 'en';
}

export function focusMobileLocalKeyboard() {
  const input = document.getElementById(INPUT_ID) as HTMLTextAreaElement | null;
  input?.focus({ preventScroll: true });
}

export function blurMobileLocalKeyboard() {
  const input = document.getElementById(INPUT_ID) as HTMLTextAreaElement | null;
  input?.blur();
}

export const MobileLocalKeyboard = () => {
  const [isLocalKeyboardOpen, setIsLocalKeyboardOpen] = useAtom(isLocalKeyboardOpenAtom);
  const setIsKeyboardEnable = useSetAtom(isKeyboardEnableAtom);

  const inputRef = useRef<HTMLTextAreaElement | null>(null);
  const keyboardRef = useRef(new KeyboardReport());
  const compositionRef = useRef(new CompositionGate());
  const queueRef = useRef(Promise.resolve());

  useEffect(() => {
    const input = inputRef.current;
    if (!input) return;

    if (isLocalKeyboardOpen) {
      requestAnimationFrame(() => input.focus({ preventScroll: true }));
      return;
    }

    input.blur();
  }, [isLocalKeyboardOpen]);

  function enqueue(action: () => void | Promise<void>) {
    queueRef.current = queueRef.current.then(action, action).catch(() => undefined);
  }

  function sendReport(report: Uint8Array) {
    const data = new Uint8Array([MessageEvent.Keyboard, ...report]);
    client.send(data);
  }

  function sendKey(code: string) {
    enqueue(() => {
      const keyboard = keyboardRef.current;
      sendReport(keyboard.keyDown(code));
      sendReport(keyboard.keyUp(code));
      sendReport(keyboard.reset());
    });
  }

  function sendText(text: string) {
    if (!text) return;
    enqueue(async () => {
      // The backend refuses characters the chosen layout cannot type, by
      // name; a silent queue would make them look typed.
      const rsp: any = await paste(text, getPasteLanguage());
      if (rsp?.code !== 0) {
        message.error(rsp?.msg || 'paste failed');
      }
    });
  }

  function resetInputValue() {
    if (inputRef.current) {
      inputRef.current.value = '';
    }
  }

  function handleBeforeInput(event: FormEvent<HTMLTextAreaElement>) {
    const nativeEvent = event.nativeEvent as InputEvent;
    if (nativeEvent.inputType === 'deleteContentBackward') {
      event.preventDefault();
      sendKey('Backspace');
      resetInputValue();
      return;
    }

    if (
      nativeEvent.inputType === 'insertLineBreak' ||
      nativeEvent.inputType === 'insertParagraph'
    ) {
      event.preventDefault();
      sendKey('Enter');
      resetInputValue();
    }
  }

  function handleInput(event: FormEvent<HTMLTextAreaElement>) {
    const nativeEvent = event.nativeEvent as InputEvent;
    const value = compositionRef.current.input(
      inputRef.current?.value || '',
      nativeEvent.isComposing
    );
    if (value === null) return;

    sendText(value.replace(/\r\n/g, '\n'));
    resetInputValue();
  }

  function handleCompositionStart() {
    compositionRef.current.start();
  }

  function handleCompositionEnd() {
    const value = compositionRef.current.end(inputRef.current?.value || '');
    if (value === null) return;

    sendText(value.replace(/\r\n/g, '\n'));
    resetInputValue();
  }

  function handlePaste(event: ClipboardEvent<HTMLTextAreaElement>) {
    const text = event.clipboardData.getData('text/plain');
    if (!text) return;

    event.preventDefault();
    sendText(text);
    resetInputValue();
  }

  function handleKeyDown(event: KeyboardEvent<HTMLTextAreaElement>) {
    if (event.key === 'Backspace') {
      event.preventDefault();
      sendKey('Backspace');
      return;
    }

    if (event.key === 'Enter') {
      event.preventDefault();
      sendKey('Enter');
      resetInputValue();
    }
  }

  function handleFocus() {
    setIsLocalKeyboardOpen(true);
    setIsKeyboardEnable(false);
  }

  function handleBlur() {
    setIsLocalKeyboardOpen(false);
    setIsKeyboardEnable(true);
    resetInputValue();
  }

  return (
    <textarea
      id={INPUT_ID}
      ref={inputRef}
      aria-label="Mobile local keyboard input"
      autoCapitalize="off"
      autoComplete="off"
      autoCorrect="off"
      className="fixed bottom-0 left-0 z-[1200] h-px w-px resize-none opacity-0"
      inputMode="text"
      rows={1}
      spellCheck={false}
      tabIndex={-1}
      onBeforeInput={handleBeforeInput}
      onCompositionEnd={handleCompositionEnd}
      onCompositionStart={handleCompositionStart}
      onFocus={handleFocus}
      onInput={handleInput}
      onKeyDown={handleKeyDown}
      onBlur={handleBlur}
      onPaste={handlePaste}
    />
  );
};

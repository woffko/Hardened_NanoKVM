// Text entered through an IME (Russian, Korean, Japanese and others) arrives
// as a run of input events while the composition is open, each carrying the
// partial text so far. Sending each of them typed every fragment. The gate
// holds the text until the composition ends and releases it once.
export class CompositionGate {
  private composing = false;

  start(): void {
    this.composing = true;
  }

  /** The text to send for an input event, or null while a composition is open. */
  input(value: string, isComposing: boolean): string | null {
    if (isComposing || this.composing) {
      return null;
    }
    return value || null;
  }

  /** The composition's final text, to send once. */
  end(value: string): string | null {
    this.composing = false;
    return value || null;
  }
}

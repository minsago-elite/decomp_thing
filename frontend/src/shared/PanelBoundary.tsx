import { panelBoundaryCopy as copy } from '../copy/shell';
import { Component, Fragment } from 'preact';
import type { ComponentChildren } from 'preact';
import { textMessage } from './messages';

type PanelProps = { name: string; children: ComponentChildren };
type PanelState = { failed: boolean; attempt: number };

/**
 * Isolates one independent panel (#628). A render failure replaces only that panel with a fixed
 * notice; the route heading, navigation and sibling panels stay usable. No exception text, stack
 * or server detail is displayed, and retrying only re-renders the panel, which repeats its own
 * safe reads and never a command.
 */
export class PanelBoundary extends Component<PanelProps, PanelState> {
  override state: PanelState = { failed: false, attempt: 0 };

  static override getDerivedStateFromError(): Partial<PanelState> {
    return { failed: true };
  }

  override render() {
    if (this.state.failed) {
      return (
        <section class="notice notice-error panel-failure" role="alert" aria-label={textMessage(copy.title, { panel: this.props.name })}>
          <h2>{textMessage(copy.title, { panel: this.props.name })}</h2>
          <p>{copy.explanation}</p>
          <button type="button" onClick={() => this.setState(({ attempt }) => ({ failed: false, attempt: attempt + 1 }))}>{copy.tryAgain}</button>
        </section>
      );
    }
    // A new key remounts the panel so a retry starts from fresh state; no wrapper element is added.
    return <Fragment key={this.state.attempt}>{this.props.children}</Fragment>;
  }
}

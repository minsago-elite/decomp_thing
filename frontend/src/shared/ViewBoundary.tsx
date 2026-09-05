import { Component } from 'preact';
import type { ComponentChildren } from 'preact';
import { ErrorBoundary as AsyncBoundary } from 'preact-iso/lazy';

type BoundaryProps = { children: ComponentChildren };
type BoundaryState = { failed: boolean };

export class ViewBoundary extends Component<BoundaryProps, BoundaryState> {
  override state: BoundaryState = { failed: false };

  static override getDerivedStateFromError(): BoundaryState {
    return { failed: true };
  }

  override render() {
    if (this.state.failed) {
      return (
        <section class="notice notice-error" aria-labelledby="view-error-title" role="alert">
          <h1 id="view-error-title">This view could not be opened</h1>
          <p>Your work remains on the server. Try opening the view again.</p>
          <button type="button" onClick={() => this.setState({ failed: false })}>Try again</button>
        </section>
      );
    }
    return <AsyncBoundary>{this.props.children}</AsyncBoundary>;
  }
}

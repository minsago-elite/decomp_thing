import { render } from 'preact';
import { App } from './app/App';
import { normalizeBasePath } from './app/paths';
import { readBuildIdentity } from './app/buildIdentity';
import { takeBootstrapFragment } from './session/fragment';
import { createSessionGateway } from './session/gateway';
import { createBrowserSession } from './session/session';
import './styles/app.css';

function mount() {
  const fragment = takeBootstrapFragment(window.location, window.history);
  const root = document.getElementById('app');
  if (!root) throw new Error('The application mount point is missing.');

  try {
    const basePath = normalizeBasePath(
      document.querySelector<HTMLMetaElement>('meta[name="decomp-base-path"]')?.content ?? '/',
    );
    const session = createBrowserSession(createSessionGateway(basePath), basePath);
    void session.initialize(fragment);
    render(<App basePath={basePath} identity={readBuildIdentity(document)} session={session} />, root);
    window.addEventListener('hashchange', () => {
      void session.connect(takeBootstrapFragment(window.location, window.history));
    });
  } catch {
    const heading = document.createElement('h1');
    heading.textContent = 'The workbench could not start';
    const message = document.createElement('p');
    message.textContent = 'Check the application configuration and reload this page.';
    root.replaceChildren(heading, message);
  }
}

mount();

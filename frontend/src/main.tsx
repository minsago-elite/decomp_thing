import { render } from 'preact';
import { App } from './app/App';
import { normalizeBasePath } from './app/paths';
import './styles/app.css';

const root = document.getElementById('app');
if (!root) throw new Error('The application mount point is missing.');

try {
  const basePath = normalizeBasePath(
    document.querySelector<HTMLMetaElement>('meta[name="decomp-base-path"]')?.content ?? '/',
  );
  render(<App basePath={basePath} />, root);
} catch {
  const heading = document.createElement('h1');
  heading.textContent = 'The workbench could not start';
  const message = document.createElement('p');
  message.textContent = 'Check the application configuration and reload this page.';
  root.replaceChildren(heading, message);
}

import '../src/styles/app.css';
import './catalogue.css';

type Catalogue = {
  label: string;
  schemaSha256: string;
  scenarios: { name: string; description: string; jobPath: string; runPath: string; reportPath: string }[];
  downloadPath: string;
};

const root = document.querySelector('#fixture-view');
if (!root) throw new Error('Fixture catalogue mount is missing.');
const message = document.createElement('p');
message.setAttribute('role', 'status');
const output = document.createElement('pre');
output.tabIndex = 0;
output.setAttribute('aria-label', 'Simulated API response');
root.append(message, output);

try {
  const response = await fetch('./catalogue.json', { credentials: 'same-origin' });
  if (!response.ok) throw new Error('Fixture catalogue is unavailable.');
  const catalogue = await response.json() as Catalogue;
  const schema = document.createElement('p');
  schema.textContent = `Shared schema SHA-256: ${catalogue.schemaSha256}`;
  root.prepend(schema);
  for (const scenario of catalogue.scenarios) {
    const section = document.createElement('section');
    const title = document.createElement('h2');
    title.textContent = scenario.name;
    const description = document.createElement('p');
    description.textContent = scenario.description;
    section.append(title, description);
    for (const [label, path] of [['Job', scenario.jobPath], ['Run', scenario.runPath], ['Report', scenario.reportPath], ['Poll events', `${scenario.runPath}/events?transport=poll`]]) {
      const button = document.createElement('button');
      button.type = 'button';
      button.textContent = label ?? '';
      button.addEventListener('click', () => {
        void fetch(path ?? '', { credentials: 'same-origin' }).then(async (result) => {
          output.textContent = JSON.stringify(await result.json(), null, 2);
          message.textContent = `${scenario.name}: ${label ?? ''} returned HTTP ${String(result.status)} (simulated).`;
        }).catch(() => { message.textContent = 'Simulated response could not be loaded.'; });
      });
      section.append(button);
    }
    const events = document.createElement('button');
    events.type = 'button';
    events.textContent = 'Read one SSE event';
    events.addEventListener('click', () => {
      const stream = new EventSource(`${scenario.runPath}/events`);
      stream.onmessage = (event) => {
        output.textContent = String(event.data);
        message.textContent = `${scenario.name}: one simulated SSE event received; connection closed.`;
        stream.close();
      };
      stream.onerror = () => { message.textContent = 'Simulated stream unavailable.'; stream.close(); };
    });
    section.append(events);
    root.insertBefore(section, message);
  }
  const download = document.createElement('a');
  download.href = catalogue.downloadPath;
  download.textContent = 'Download synthetic attachment';
  root.insertBefore(download, message);
} catch {
  message.textContent = 'Fixture mode could not load its validated catalogue.';
}

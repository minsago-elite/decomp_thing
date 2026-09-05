export default function Home() {
  return (
    <section aria-labelledby="workspace-title">
      <p class="eyebrow">Reconstruction workspace</p>
      <h1 id="workspace-title">Your work, with its evidence</h1>
      <p class="lead">
        Review reconstructed source, inspect validation evidence, and follow each revision.
      </p>
      <div class="notice" aria-labelledby="availability-title">
        <h2 id="availability-title">The workbench shell is ready</h2>
        <p>
          Job browsing and workflow controls are being connected. This shell does not
          read jobs or start workflows.
        </p>
        <p>Existing command-line workflows remain available.</p>
      </div>
    </section>
  );
}

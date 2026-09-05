export default function Runtime() {
  return (
    <section aria-labelledby="runtime-title">
      <p class="eyebrow">Application</p>
      <h1 id="runtime-title">Runtime status</h1>
      <div class="notice" aria-labelledby="runtime-availability-title">
        <h2 id="runtime-availability-title">Runtime information is not connected</h2>
        <p>
          Tool availability and workflow capabilities will be reported by the server.
          Opening this page does not run a tool or check a provider.
        </p>
      </div>
    </section>
  );
}

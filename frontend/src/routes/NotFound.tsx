export function NotFound({ homePath }: { homePath: string }) {
  return (
    <section aria-labelledby="missing-title">
      <p class="eyebrow">Page unavailable</p>
      <h1 id="missing-title">This page could not be found</h1>
      <p>The link may be incomplete, or this view may not be available.</p>
      <a class="button-link" href={homePath}>Return to the workspace</a>
    </section>
  );
}

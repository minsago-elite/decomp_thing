import { notFoundCopy as copy } from '../copy/shell';
export function NotFound({ homePath }: { homePath: string }) {
  return (
    <section aria-labelledby="missing-title">
      <p class="eyebrow">{copy.pageUnavailable}</p>
      <h1 id="missing-title">{copy.thisPageCouldNotBeFound}</h1>
      <p>{copy.theLinkMayBeIncompleteOrThisViewMayNot}</p>
      <a class="button-link" href={homePath}>{copy.returnToTheWorkspace}</a>
    </section>
  );
}

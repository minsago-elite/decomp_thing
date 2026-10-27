import type { ComponentChildren } from 'preact';

type ParameterNames<Template extends string> = Template extends `${string}{${infer Name}}${infer Rest}`
  ? Name | ParameterNames<Rest> : never;

/** Named slots let a catalog reorder text and existing markup without interpreting HTML. */
export function message<Template extends string>(
  template: Template,
  values: { [Name in ParameterNames<Template>]: ComponentChildren },
): ComponentChildren[] {
  const parts: ComponentChildren[] = [];
  let start = 0;
  for (const match of template.matchAll(/\{([A-Za-z][A-Za-z0-9]*)\}/g)) {
    parts.push(template.slice(start, match.index));
    const name = match[1] as keyof typeof values;
    if (!Object.prototype.hasOwnProperty.call(values, name)) throw new Error('Missing display message parameter');
    parts.push(values[name]);
    start = match.index + match[0].length;
  }
  parts.push(template.slice(start));
  return parts;
}

/** Plain attributes and document titles accept text values only. */
export function textMessage<Template extends string>(
  template: Template,
  values: { [Name in ParameterNames<Template>]: string | number },
): string {
  return template.replace(/\{([A-Za-z][A-Za-z0-9]*)\}/g, (_match, parameter: string) => {
    const name = parameter as keyof typeof values;
    if (!Object.prototype.hasOwnProperty.call(values, name)) throw new Error('Missing display message parameter');
    return String(values[name]);
  });
}

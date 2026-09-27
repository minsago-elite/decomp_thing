/** The exact draft-07 subset accepted by the build-time generator. */
export interface Schema {
  $ref?: string;
  description?: string;
  type?: 'object' | 'array' | 'null' | 'boolean' | 'string' | 'number' | 'integer';
  definitions?: Record<string, Schema>;
  properties?: Record<string, Schema>;
  required?: string[];
  additionalProperties?: false;
  anyOf?: Schema[];
  oneOf?: Schema[];
  allOf?: Schema[];
  if?: Schema;
  then?: Schema;
  else?: Schema;
  enum?: unknown[];
  const?: unknown;
  pattern?: string;
  minLength?: number;
  maxLength?: number;
  minimum?: number;
  maximum?: number;
  items?: Schema;
  minItems?: number;
  maxItems?: number;
  uniqueItems?: boolean;
  format?: 'date-time';
}

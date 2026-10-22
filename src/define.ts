export type PluginSetup = (ctx: Record<string, any>) => Promise<void> | void

export interface PluginDefinition {
  id: string
  setup: PluginSetup
}

// Mirrors @opencode/plugin -> Plugin.define({ id, setup }).
// Keeping it local means the core has zero runtime dependencies and can be
// unit-tested without installing the OpenCode SDK. If you do have
// @opencode/plugin installed, swap this for Plugin.define to get full typing.
export function define(definition: PluginDefinition): PluginDefinition {
  if (!definition || typeof definition.id !== "string" || !definition.id) {
    throw new Error("opencode-guard: plugin definition requires an id")
  }
  if (typeof definition.setup !== "function") {
    throw new Error("opencode-guard: plugin definition requires a setup function")
  }
  return definition
}

#!/usr/bin/env bun

const plugins = ['loki_test', 'scim_test', 'api_test'] // 'mongodb_test'

for (const plugin of plugins) {
  await import(`./lib/plugin-${plugin}.ts`)
}

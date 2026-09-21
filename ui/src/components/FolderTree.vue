<script setup lang="ts">
import { computed, ref } from 'vue'
import type { FolderNode } from '@/api/types'

const props = defineProps<{ nodes: FolderNode[]; selected: string | null; depth?: number }>()
const emit = defineEmits<{ select: [id: string | null] }>()
const open = ref<Record<string, boolean>>({})
const level = computed(() => props.depth ?? 0)

function toggle(id: string): void {
  open.value[id] = !open.value[id]
}
</script>

<template>
  <ul class="folder-tree" :class="{ 'folder-tree--root': level === 0 }" role="tree" :aria-label="level === 0 ? 'Folders' : undefined">
    <li v-if="level === 0" role="treeitem" :aria-selected="selected === null">
      <button type="button" class="folder-tree__item" :class="{ 'folder-tree__item--active': selected === null }" data-test="folder-root" @click="emit('select', null)">
        <v-icon icon="mdi-home-outline" size="small" class="mr-1" />
        Root
      </button>
    </li>
    <li v-for="n in nodes" :key="n.folder.id" role="treeitem" :aria-expanded="n.children.length ? !!open[n.folder.id] : undefined" :aria-selected="selected === n.folder.id">
      <div class="d-flex align-center" :style="{ paddingLeft: level * 12 + 'px' }">
        <button
          v-if="n.children.length"
          type="button"
          class="folder-tree__toggle"
          :aria-label="(open[n.folder.id] ? 'Collapse ' : 'Expand ') + n.folder.name"
          :data-test="'folder-toggle-' + n.folder.id"
          @click="toggle(n.folder.id)"
        >
          <v-icon :icon="open[n.folder.id] ? 'mdi-chevron-down' : 'mdi-chevron-right'" size="small" />
        </button>
        <span v-else class="folder-tree__spacer" />
        <button
          type="button"
          class="folder-tree__item"
          :class="{ 'folder-tree__item--active': selected === n.folder.id }"
          :data-test="'folder-' + n.folder.id"
          @click="emit('select', n.folder.id)"
        >
          <v-icon :icon="open[n.folder.id] ? 'mdi-folder-open-outline' : 'mdi-folder-outline'" size="small" class="mr-1" />
          {{ n.folder.name }}
        </button>
      </div>
      <FolderTree v-if="n.children.length && open[n.folder.id]" :nodes="n.children" :selected="selected" :depth="level + 1" @select="emit('select', $event)" />
    </li>
  </ul>
</template>

<style scoped>
.folder-tree {
  list-style: none;
  padding: 0;
  margin: 0;
}
.folder-tree__item,
.folder-tree__toggle {
  /* Plain buttons: drop the browser chrome, inherit the theme's text colour. */
  border: 0;
  background: transparent;
  color: inherit;
  font: inherit;
  cursor: pointer;
}
.folder-tree__item {
  display: inline-flex;
  align-items: center;
  padding: 4px 8px;
  border-radius: 4px;
  width: 100%;
  text-align: left;
}
.folder-tree__item:hover {
  background: rgba(var(--v-theme-on-surface), var(--v-hover-opacity));
}
.folder-tree__item--active {
  background: rgba(var(--v-theme-primary), 0.12);
  color: rgb(var(--v-theme-primary));
}
.folder-tree__toggle {
  width: 24px;
  height: 24px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
}
.folder-tree__spacer {
  display: inline-block;
  width: 24px;
}
</style>

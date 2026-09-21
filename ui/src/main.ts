// Standalone development entry: mounts the warden routes in a bare Vuetify app
// against the gateway (npm run dev). In the platform the shell mounts
// ./routes and ./nav from the federated remote instead.
import { createApp } from 'vue'
import { createPinia } from 'pinia'
import { createRouter, createWebHistory } from 'vue-router'
import { createVuetify } from 'vuetify'
import { abilitiesPlugin } from '@casl/vue'
import { createMongoAbility } from '@casl/ability'
import 'vuetify/styles'
import '@mdi/font/css/materialdesignicons.css'
import { routes } from '@/remote/routes'

const app = createApp({ template: '<v-app><v-main><router-view /></v-main></v-app>' })
app.use(createPinia())
app.use(createRouter({ history: createWebHistory('/'), routes }))
app.use(createVuetify({ theme: { defaultTheme: 'light', themes: { light: { variables: { 'medium-emphasis-opacity': 0.74 } } } } }))
app.use(abilitiesPlugin, createMongoAbility([{ action: 'manage', subject: 'all' }]), { useGlobalProperties: true })
app.mount('#app')

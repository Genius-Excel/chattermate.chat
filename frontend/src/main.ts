import './assets/styles/main.css'
import '@/assets/base.css'

import { createApp } from 'vue'
import { createPinia } from 'pinia'
import VueApexCharts from 'vue3-apexcharts'
import App from './App.vue'
import router from './router'
import { initializeFirebase } from './services/firebase'
import 'floating-vue/dist/style.css'
import FloatingVue from 'floating-vue'

const app = createApp(App)

app.use(createPinia())
app.use(router)
app.use(VueApexCharts)
app.use(FloatingVue)

initializeFirebase()

app.mount('#app')

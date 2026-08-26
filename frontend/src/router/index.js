import { createRouter, createWebHistory } from 'vue-router'
import HomeView from '../views/HomeView.vue'
import AuthCallback from '../views/AuthCallback.vue'
import PostLogout from '../views/PostLogout.vue'

export const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: HomeView },
    { path: '/auth-callback', component: AuthCallback },
    { path: '/auth-logout', component: PostLogout },
  ],
})

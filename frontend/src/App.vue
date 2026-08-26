<template>
  <div class="app">
    <header>
      <h1>Legacy Auth Demo</h1>
      <nav>
        <router-link to="/">Home</router-link>
        <span v-if="user" class="who">
          {{ user.profile.name }}
          <button @click="logout">Sign out</button>
        </span>
        <button v-else @click="login">Sign in</button>
      </nav>
    </header>
    <main>
      <router-view @auth-changed="refreshUser" />
    </main>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { userManager, getUser, login, logout } from './auth'

const user = ref(null)

async function refreshUser() {
  user.value = await getUser()
}

onMounted(refreshUser)
</script>

<style>
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: 'Segoe UI', system-ui, sans-serif;
  background: #f4f5f7;
  color: #222;
}
.app { max-width: 900px; margin: 0 auto; padding: 1rem; }
header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  border-bottom: 2px solid #2c3e50;
  padding-bottom: 0.5rem;
}
h1 { font-size: 1.3rem; color: #2c3e50; }
nav { display: flex; gap: 1rem; align-items: center; }
.who { display: flex; gap: 0.75rem; align-items: center; font-weight: 600; }
button {
  background: #2c3e50;
  color: white;
  border: none;
  border-radius: 4px;
  padding: 0.45rem 1rem;
  cursor: pointer;
}
button:hover { background: #46627f; }
.card {
  background: white;
  border-radius: 8px;
  padding: 1rem 1.25rem;
  margin-top: 1rem;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.12);
}
.card h3 { margin-top: 0; }
pre {
  background: #1e1e1e;
  color: #d4d4d4;
  padding: 0.75rem;
  border-radius: 6px;
  overflow: auto;
  max-height: 400px;
  font-size: 0.85rem;
}
.error-text { color: #b00020; font-weight: 600; }
.forbidden { color: #a15c00; font-weight: 600; }
.ok-badge { color: #1b5e20; font-weight: 600; }
</style>

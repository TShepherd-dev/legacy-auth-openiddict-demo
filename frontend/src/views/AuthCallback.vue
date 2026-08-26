<template>
  <div class="card">
    <h3>Signing you in…</h3>
    <p v-if="error" class="error-text">{{ error }}</p>
    <p v-else>Completing the authorization code flow.</p>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { userManager } from '../auth'

const error = ref(null)
const router = useRouter()

onMounted(async () => {
  try {
    await userManager.signinCallback()
  } catch (e) {
    error.value = e.message
    return
  }
  router.replace('/')
})
</script>

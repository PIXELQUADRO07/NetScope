document.getElementById('btn-rev').addEventListener('click', doReverse)
document.getElementById('btn-ssl').addEventListener('click', doSSL)
const { createApp } = Vue
const { createRouter, createWebHistory } = VueRouter

// helper for history persistence
function pushHistory(entry){
  try{
    const key = 'scan_history'
    const raw = localStorage.getItem(key)
    const arr = raw ? JSON.parse(raw) : []
    arr.unshift(entry)
    // keep last 100
    localStorage.setItem(key, JSON.stringify(arr.slice(0,100)))
  }catch(e){ console.warn('history push failed', e) }
}

const Home = {
  template: '#home',
  data(){
    return {
      localConcurrency: 20,
      localLoading: false,
      localResult: null,
      revIP: '',
      revLoading: false,
      revResult: null,
      sslHost: '',
      sslPort: '443',
      sslLoading: false,
      sslResult: null,
    }
  },
  methods:{
    pretty(v){ try{ return JSON.stringify(v, null, 2) }catch(e){ return String(v) } },
    async localScan(){
      this.localLoading = true
      this.localResult = null
      try{
        const res = await fetch(`/api/scan/local?concurrency=${this.localConcurrency}`)
        this.localResult = await res.json()
        pushHistory({ ts: Date.now(), type: 'local', params: { concurrency: this.localConcurrency }, result: this.localResult })
      }catch(e){ this.localResult = { error: String(e) } }
      finally{ this.localLoading = false }
    },
    async reverseLookup(){
      if(!this.revIP) return
      this.revLoading = true
      this.revResult = null
      try{
        const res = await fetch(`/api/reverse?ip=${encodeURIComponent(this.revIP)}`)
        this.revResult = await res.json()
        pushHistory({ ts: Date.now(), type: 'reverse', params: { ip: this.revIP }, result: this.revResult })
      }catch(e){ this.revResult = { error: String(e) } }
      finally{ this.revLoading = false }
    },
    async getSSL(){
      if(!this.sslHost) return
      this.sslLoading = true
      this.sslResult = null
      try{
        const res = await fetch(`/api/ssl?host=${encodeURIComponent(this.sslHost)}&port=${encodeURIComponent(this.sslPort)}`)
        this.sslResult = await res.json()
        pushHistory({ ts: Date.now(), type: 'ssl', params: { host: this.sslHost, port: this.sslPort }, result: this.sslResult })
      }catch(e){ this.sslResult = { error: String(e) } }
      finally{ this.sslLoading = false }
    }
  }
}

const History = {
  template: '#history',
  data(){ return { entries: [] } },
  methods:{
    load(){
      try{
        const raw = localStorage.getItem('scan_history')
        this.entries = raw ? JSON.parse(raw) : []
      }catch(e){ this.entries = [] }
    },
    clearHistory(){
      localStorage.removeItem('scan_history')
      this.entries = []
    },
    pretty(v){ try{ return JSON.stringify(v, null, 2) }catch(e){ return String(v) } },
    formatTS(ts){ return new Date(ts).toLocaleString() }
  },
  mounted(){ this.load() }
}

const routes = [
  { path: '/', component: Home },
  { path: '/history', component: History }
]

const router = createRouter({ history: createWebHistory(), routes })

createApp({}).use(router).mount('#app')

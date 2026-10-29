/**
 * Matra Naari - Premium Indian Ethnic Fashion E-Commerce
 * Core client application logic, state management, drawers, search, and navigation
 */

// Global Configuration
const STORE_PHONE = '918849366915';
const STORE_PHONE_DISPLAY = '+91 88493 66915';
const API_BASE = window.location.origin;

// Storage Keys
const CART_STORAGE_KEY = 'naari_cart_v1';
const WISHLIST_STORAGE_KEY = 'naari_wishlist_v1';
const USER_STORAGE_KEY = 'naari_user_v1';
const COUPON_STORAGE_KEY = 'naari_coupon_v1';
const RECENTLY_VIEWED_KEY = 'naari_recently_viewed_v1';

// Dynamic Storefront Settings Cache (hydrated from /api/banners & /api/config)
window.NAARI_STORE_SETTINGS = {
  free_shipping_threshold: 999,
  shipping_fee: 99,
  cod_enabled: true,
  announcement_enabled: true,
  promo_banner_enabled: true,
  active_promo_coupon: null
};

// Default Fallback Products Catalog
const PRODUCTS = [
  {
    id: 'straight',
    name: 'Gulmohar Straight Kurti',
    category: 'Straight Cut',
    note: 'Everyday ease, hand block-printed on fine cotton.',
    image: 'assets/hero.jpg',
    relativeImage: 'assets/hero.jpg',
    price: 1299,
    mrp: 1999,
    discountPercent: 35,
    colors: [
      { name: 'Maroon', swatch: '#6B2D31' },
      { name: 'Ivory', swatch: '#F5F2EB' },
      { name: 'Indigo', swatch: '#2A3D66' }
    ],
    sizes: ['XS', 'S', 'M', 'L', 'XL', 'XXL']
  },
  {
    id: 'aline',
    name: 'Chandni A-Line Kurti',
    category: 'A-Line',
    note: 'A soft flare with delicate thread work.',
    image: 'assets/k-aline.jpg',
    relativeImage: 'assets/k-aline.jpg',
    price: 1499,
    mrp: 2199,
    discountPercent: 32,
    colors: [
      { name: 'Ivory', swatch: '#F5F2EB' },
      { name: 'Blush', swatch: '#D88B92' }
    ],
    sizes: ['S', 'M', 'L', 'XL']
  },
  {
    id: 'anarkali',
    name: 'Genda Anarkali Kurta',
    category: 'Anarkali',
    note: 'Twirl-worthy mulmul flair with gold gota details.',
    image: 'assets/k-anarkali.jpg',
    relativeImage: 'assets/k-anarkali.jpg',
    price: 2499,
    mrp: 3499,
    discountPercent: 29,
    soldOutSizes: ['XXL'],
    colors: [
      { name: 'Marigold', swatch: '#E69A27' },
      { name: 'Maroon', swatch: '#6B2D31' },
      { name: 'Emerald', swatch: '#1C583B' },
      { name: 'Rani Pink', swatch: '#C1285C' }
    ],
    sizes: ['XS', 'S', 'M', 'L', 'XL', 'XXL']
  },
  {
    id: 'short',
    name: 'Neel Short Kurti',
    category: 'Short Kurti',
    note: 'Pair it with denims or linen pants, own the day.',
    image: 'assets/k-short.jpg',
    relativeImage: 'assets/k-short.jpg',
    price: 899,
    mrp: 1399,
    discountPercent: 36,
    colors: [
      { name: 'Indigo', swatch: '#1C335C' },
      { name: 'White', swatch: '#FFFFFF' },
      { name: 'Black', swatch: '#1F1F1F' }
    ],
    sizes: ['XS', 'S', 'M', 'L', 'XL']
  },
  {
    id: 'angrakha',
    name: 'Tulsi Angrakha',
    category: 'Angrakha',
    note: 'Overlap wrap silhouette with handmade tassel ties.',
    image: 'assets/k-angrakha.jpg',
    relativeImage: 'assets/k-angrakha.jpg',
    price: 1799,
    mrp: 2599,
    discountPercent: 31,
    colors: [
      { name: 'Sage', swatch: '#7B967D' },
      { name: 'Ivory', swatch: '#F5F2EB' }
    ],
    sizes: ['S', 'M', 'L', 'XL', 'XXL']
  },
  {
    id: 'kaftan',
    name: 'Sandhya Kaftan Kurti',
    category: 'Kaftan',
    note: 'Breezy relaxed kaftan with drawstring waist.',
    image: 'assets/k-kaftan.jpg',
    relativeImage: 'assets/k-kaftan.jpg',
    price: 1599,
    mrp: 2299,
    discountPercent: 30,
    colors: [
      { name: 'Rust', swatch: '#9E472A' },
      { name: 'Sand', swatch: '#D6C3A5' },
      { name: 'Olive', swatch: '#5A6843' }
    ],
    sizes: ['Free Size']
  },
  {
    id: 'coord',
    name: 'Gulabi Kurta Set',
    category: 'Co-ord Set',
    note: 'Kurta and pants, crafted in matching elegance.',
    image: 'assets/k-coord.jpg',
    relativeImage: 'assets/k-coord.jpg',
    price: 2199,
    mrp: 3199,
    discountPercent: 31,
    colors: [
      { name: 'Dusty Pink', swatch: '#C4808C' },
      { name: 'Powder Blue', swatch: '#8FA9BF' }
    ],
    sizes: ['XS', 'S', 'M', 'L', 'XL', 'XXL']
  }
];

const CATEGORIES = ['Straight Cut', 'A-Line', 'Anarkali', 'Short Kurti', 'Angrakha', 'Kaftan', 'Co-ord Set'];

function formatPrice(amount) {
  return '₹' + Math.round(amount || 0).toLocaleString('en-IN');
}

// ================= Toast Notification System =================
class ToastManager {
  constructor() {
    this.container = document.getElementById('naari-toast-container');
    if (!this.container) {
      this.container = document.createElement('div');
      this.container.id = 'naari-toast-container';
      this.container.className = 'fixed bottom-5 right-5 z-[100] flex flex-col gap-2 max-w-sm w-full px-4 pointer-events-none';
      document.body.appendChild(this.container);
    }
  }

  show(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `pointer-events-auto transform transition-all duration-300 ease-out flex items-center gap-3 px-4 py-3 rounded shadow-xl text-sm font-sans ${
      type === 'error'
        ? 'bg-[#2A1810] text-[#FFB4AB] border border-[#93000A]/60'
        : type === 'success'
        ? 'bg-[#1D2B1E] text-[#D1F2D9] border border-[#3E6B47]/70'
        : 'bg-[#2E1E1C] text-[#F9EBEA] border border-[#6B2D31]/60'
    } translate-y-4 opacity-0`;

    const icon = type === 'error' ? '⚠ ' : type === 'success' ? '✓ ' : '✿ ';
    toast.innerHTML = `<span class="shrink-0 text-base font-bold">${icon}</span><span class="flex-1 font-medium">${message}</span>`;
    this.container.appendChild(toast);

    requestAnimationFrame(() => {
      toast.classList.remove('translate-y-4', 'opacity-0');
      toast.classList.add('translate-y-0', 'opacity-100');
    });

    setTimeout(() => {
      toast.classList.remove('translate-y-0', 'opacity-100');
      toast.classList.add('translate-y-4', 'opacity-0');
      setTimeout(() => {
        if (toast.parentElement) toast.remove();
      }, 300);
    }, 3800);
  }

  success(msg) { this.show(msg, 'success'); }
  error(msg) { this.show(msg, 'error'); }
  info(msg) { this.show(msg, 'info'); }
}

let toastInstance;
function getToast() {
  if (!toastInstance) toastInstance = new ToastManager();
  return toastInstance;
}

// ================= Shopping Bag State =================
function getCart() {
  try {
    const raw = localStorage.getItem(CART_STORAGE_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch (e) {
    return [];
  }
}

function saveCart(cart) {
  try {
    localStorage.setItem(CART_STORAGE_KEY, JSON.stringify(cart));
  } catch (e) {}
  updateHeaderBadges();
  renderCartDrawerContent();
  // Dispatch custom cart-updated event for views
  window.dispatchEvent(new CustomEvent('naari:cartUpdated', { detail: { cart } }));
}

function addToCart(item, openDrawer = true) {
  const cart = getCart();
  const key = `${item.id}-${item.color}-${item.size}`;
  const existing = cart.find(i => i.key === key);
  if (existing) {
    existing.qty += (item.qty || 1);
  } else {
    cart.push({ ...item, qty: item.qty || 1, key });
  }
  saveCart(cart);
  getToast().success(`Added "${item.name}" to your bag!`);
  if (openDrawer) {
    openCartDrawer();
  }
}

function updateCartQty(key, newQty) {
  let cart = getCart();
  if (newQty <= 0) {
    cart = cart.filter(i => i.key !== key);
  } else {
    const item = cart.find(i => i.key === key);
    if (item) item.qty = newQty;
  }
  saveCart(cart);
}

function removeCartItem(key) {
  let cart = getCart();
  cart = cart.filter(i => i.key !== key);
  saveCart(cart);
  getToast().info('Item removed from your bag.');
}

function getCartCount() {
  return getCart().reduce((sum, item) => sum + item.qty, 0);
}

function getCartSubtotal() {
  return getCart().reduce((sum, item) => sum + (item.price * item.qty), 0);
}

// Backwards-compatible alias used by checkout.html
function getCartTotal() {
  return getCartSubtotal();
}

// ================= Recently Viewed Products =================
function trackRecentlyViewed(product) {
  if (!product || !product.id) return;
  try {
    const raw = localStorage.getItem(RECENTLY_VIEWED_KEY);
    let list = raw ? JSON.parse(raw) : [];
    list = list.filter(item => item.id !== product.id);
    list.unshift({
      id: product.id,
      name: product.name,
      category: product.category,
      fabric: product.fabric || '',
      style: product.style || '',
      price: product.price,
      mrp: product.mrp,
      discountPercent: product.discountPercent || (product.mrp > product.price ? Math.round((product.mrp - product.price) / product.mrp * 100) : 0),
      image: product.relative_image || product.image || product.relativeImage,
      sizes: product.sizes || ['XS', 'S', 'M', 'L', 'XL'],
      soldOutSizes: product.soldOutSizes || [],
      colors: product.colors || [{ name: 'Maroon', swatch: '#6B2D31' }],
      is_new: product.is_new || 0,
      is_bestseller: product.is_bestseller || 0,
      stock: product.stock !== undefined ? product.stock : 25
    });
    localStorage.setItem(RECENTLY_VIEWED_KEY, JSON.stringify(list.slice(0, 8)));
  } catch (e) {}
}

function getRecentlyViewed(excludeId = '') {
  try {
    const raw = localStorage.getItem(RECENTLY_VIEWED_KEY);
    const list = raw ? JSON.parse(raw) : [];
    return excludeId ? list.filter(item => item.id !== excludeId) : list;
  } catch (e) {
    return [];
  }
}

// ================= Shared Product Card Renderer =================
function renderProductCard(p) {
  const isSaved = isInWishlist(p.id);
  const imgSrc = p.relative_image || p.image || p.relativeImage || 'assets/hero.jpg';
  const disc = p.discountPercent || (p.mrp > p.price ? Math.round(((p.mrp - p.price) / p.mrp) * 100) : 0);
  const availSizes = (p.sizes || ['XS', 'S', 'M', 'L', 'XL']).filter(s => !(p.soldOutSizes || []).includes(s));
  const outOfStock = p.stock !== undefined && p.stock <= 0;
  const subMeta = [p.category, p.fabric].filter(Boolean).join(' · ');

  let badgeHtml = '';
  if (outOfStock) {
    badgeHtml = `<span class="bg-foreground text-background px-2 py-0.5 text-[10px] uppercase tracking-widest font-semibold shadow-sm">Sold Out</span>`;
  } else if (p.is_bestseller) {
    badgeHtml = `<span class="bg-primary text-primary-foreground px-2 py-0.5 text-[10px] uppercase tracking-widest font-semibold shadow-sm">Bestseller</span>`;
  } else if (p.is_new) {
    badgeHtml = `<span class="bg-accent text-accent-foreground px-2 py-0.5 text-[10px] uppercase tracking-widest font-semibold shadow-sm">New Arrival</span>`;
  }

  return `
    <article class="group flex flex-col bg-card/50 ring-1 ring-border rounded-sm overflow-hidden hover:shadow-lg transition duration-300" data-product-id="${p.id}">
      <div class="relative aspect-[3/4] overflow-hidden bg-muted">
        <a href="product.html?id=${p.id}" class="block h-full w-full">
          <img
            src="${imgSrc}"
            alt="${p.name}"
            loading="lazy"
            onerror="this.onerror=null;this.src='assets/hero.jpg';"
            class="h-full w-full object-cover transition duration-700 group-hover:scale-105"
          />
        </a>

        <!-- Top Badges (Only shown when justified by actual data) -->
        <div class="absolute top-2.5 left-2.5 flex flex-col gap-1 pointer-events-none">
          ${badgeHtml}
          ${disc > 0 ? `<span class="bg-card/95 text-primary px-2 py-0.5 text-[10px] font-bold tracking-wider shadow-sm border border-primary/20">${disc}% OFF</span>` : ''}
        </div>

        <!-- Wishlist Toggle Button -->
        <button
          type="button"
          class="wishlist-toggle-btn absolute top-2.5 right-2.5 h-9 w-9 rounded-full bg-card/90 backdrop-blur-sm flex items-center justify-center text-foreground hover:text-primary shadow transition cursor-pointer ${isSaved ? 'active' : ''}"
          data-product-id="${p.id}"
          aria-label="Save ${p.name} to wishlist"
        >
          <svg class="h-4 w-4" fill="${isSaved ? '#6B2D31' : 'none'}" stroke="${isSaved ? '#6B2D31' : 'currentColor'}" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8" d="M4.318 6.318a4.5 4.5 0 000 6.364L12 20.364l7.682-7.682a4.5 4.5 0 00-6.364-6.364L12 7.636l-1.318-1.318a4.5 4.5 0 00-6.364 0z"/>
          </svg>
        </button>

        <!-- Quick Add to Bag Overlay -->
        <div class="quick-add-bar absolute inset-x-0 bottom-0 p-2.5 bg-gradient-to-t from-black/75 via-black/40 to-transparent flex flex-col gap-1.5">
          ${outOfStock ? `
            <span class="w-full bg-muted text-muted-foreground py-2 text-[11px] uppercase tracking-[0.15em] font-semibold text-center">Out of Stock</span>
          ` : `
            <button
              type="button"
              class="card-quick-add-btn w-full bg-card/95 hover:bg-primary hover:text-primary-foreground text-foreground py-2 text-[11px] uppercase tracking-[0.15em] font-semibold transition shadow cursor-pointer"
              data-id="${p.id}"
            >
              + Quick Add (${availSizes[0] || 'M'})
            </button>
          `}
        </div>
      </div>

      <!-- Product Details -->
      <div class="p-3.5 flex-1 flex flex-col justify-between bg-card/40">
        <div>
          <p class="text-[10px] uppercase tracking-[0.16em] text-muted-foreground truncate">${subMeta}</p>
          <a href="product.html?id=${p.id}" class="mt-0.5 block font-display text-lg font-semibold leading-snug hover:text-primary transition truncate">${p.name}</a>
        </div>

        <div class="mt-2 pt-2 border-t border-border/50">
          <div class="flex items-baseline gap-2 flex-wrap">
            <span class="font-display text-lg font-semibold text-primary">${formatPrice(p.price)}</span>
            ${p.mrp && p.mrp > p.price ? `<span class="text-xs line-through text-muted-foreground">${formatPrice(p.mrp)}</span>` : ''}
            ${disc > 0 ? `<span class="text-[11px] font-semibold text-emerald-800">(${disc}% OFF)</span>` : ''}
          </div>
          <div class="mt-1.5 flex items-center justify-between gap-1 text-[11px] text-muted-foreground">
            <span class="truncate">Sizes: <strong class="text-foreground font-normal">${availSizes.join(', ') || 'Sold Out'}</strong></span>
            ${(p.colors && p.colors.length > 0) ? `
              <span class="flex items-center gap-1 shrink-0" title="${p.colors.map(c => c.name).join(', ')}">
                ${p.colors.slice(0, 3).map(c => `<span class="inline-block h-2.5 w-2.5 rounded-full ring-1 ring-border" style="background:${c.swatch}"></span>`).join('')}
              </span>
            ` : ''}
          </div>
        </div>
      </div>
    </article>
  `;
}

function attachProductCardEvents(container, catalogList) {
  if (!container) return;
  const list = catalogList || PRODUCTS;

  container.querySelectorAll('.wishlist-toggle-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      const pid = btn.dataset.productId;
      const prod = list.find(x => x.id === pid) || PRODUCTS.find(x => x.id === pid);
      if (prod) toggleWishlist(prod);
    });
  });

  container.querySelectorAll('.card-quick-add-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      const pid = btn.dataset.id;
      const prod = list.find(x => x.id === pid) || PRODUCTS.find(x => x.id === pid);
      if (prod) {
        const availSizes = (prod.sizes || ['M']).filter(s => !(prod.soldOutSizes || []).includes(s));
        if (availSizes.length === 0 || (prod.stock !== undefined && prod.stock <= 0)) {
          getToast().error('Sorry, this kurti is currently out of stock.');
          return;
        }
        addToCart({
          id: prod.id,
          name: prod.name,
          color: prod.colors && prod.colors[0] ? prod.colors[0].name : 'Standard',
          size: availSizes[0] || 'M',
          price: prod.price,
          mrp: prod.mrp,
          image: prod.relative_image || prod.image || prod.relativeImage,
          qty: 1
        });
      }
    });
  });
}

// ================= Wishlist State =================
function getWishlist() {
  try {
    const raw = localStorage.getItem(WISHLIST_STORAGE_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch (e) {
    return [];
  }
}

function saveWishlist(list) {
  try {
    localStorage.setItem(WISHLIST_STORAGE_KEY, JSON.stringify(list));
  } catch (e) {}
  updateHeaderBadges();
  updateWishlistHeartButtons();
  renderWishlistDrawerContent();
  window.dispatchEvent(new CustomEvent('naari:wishlistUpdated', { detail: { wishlist: list } }));
}

function toggleWishlist(product) {
  let list = getWishlist();
  const exists = list.some(item => item.id === product.id);
  if (exists) {
    list = list.filter(item => item.id !== product.id);
    saveWishlist(list);
    getToast().info(`Removed "${product.name}" from your wishlist.`);
  } else {
    list.push({
      id: product.id,
      name: product.name,
      price: product.price,
      mrp: product.mrp,
      image: product.image || product.relativeImage,
      category: product.category,
      sizes: product.sizes || ['XS', 'S', 'M', 'L', 'XL']
    });
    saveWishlist(list);
    getToast().success(`Saved "${product.name}" to your wishlist! ✿`);
  }
}

function isInWishlist(pid) {
  return getWishlist().some(item => item.id === pid);
}

function updateWishlistHeartButtons() {
  const buttons = document.querySelectorAll('.wishlist-toggle-btn');
  buttons.forEach(btn => {
    const pid = btn.dataset.productId;
    const isSaved = isInWishlist(pid);
    btn.classList.toggle('active', isSaved);
    const svg = btn.querySelector('svg');
    if (svg) {
      if (isSaved) {
        svg.setAttribute('fill', '#6B2D31');
        svg.setAttribute('stroke', '#6B2D31');
      } else {
        svg.setAttribute('fill', 'none');
        svg.setAttribute('stroke', 'currentColor');
      }
    }
  });
}

// ================= Customer User Auth State =================
function getUserSession() {
  try {
    const raw = localStorage.getItem(USER_STORAGE_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch (e) {
    return null;
  }
}

function setUserSession(token, user) {
  try {
    localStorage.setItem(USER_STORAGE_KEY, JSON.stringify({ token, user }));
  } catch (e) {}
  updateHeaderBadges();
}

function clearUserSession() {
  try {
    localStorage.removeItem(USER_STORAGE_KEY);
  } catch (e) {}
  updateHeaderBadges();
}

// ================= Active Coupon State =================
function getActiveCoupon() {
  try {
    const raw = localStorage.getItem(COUPON_STORAGE_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch (e) {
    return null;
  }
}

function setActiveCoupon(couponObj) {
  try {
    if (couponObj) {
      localStorage.setItem(COUPON_STORAGE_KEY, JSON.stringify(couponObj));
    } else {
      localStorage.removeItem(COUPON_STORAGE_KEY);
    }
  } catch (e) {}
  renderCartDrawerContent();
  window.dispatchEvent(new CustomEvent('naari:couponUpdated', { detail: { coupon: couponObj } }));
}

// ================= Header Badges & UI Sync =================
function updateHeaderBadges() {
  const bagCount = getCartCount();
  const wishCount = getWishlist().length;
  const userSession = getUserSession();

  // Bag counters
  document.querySelectorAll('.bag-count-badge, #header-bag-count').forEach(b => {
    b.textContent = bagCount;
    b.style.display = bagCount > 0 ? 'inline-flex' : 'none';
  });

  // Wishlist counters
  document.querySelectorAll('.wishlist-count-badge').forEach(b => {
    b.textContent = wishCount;
    b.style.display = wishCount > 0 ? 'inline-flex' : 'none';
  });

  // User label
  document.querySelectorAll('.header-user-label').forEach(el => {
    if (userSession && userSession.user && userSession.user.name) {
      el.textContent = userSession.user.name.split(' ')[0];
    } else {
      el.textContent = 'Account';
    }
  });
}

// Backwards-compatible alias used by checkout.html
function updateHeaderBagCount() {
  updateHeaderBadges();
}

// Ensure every storefront header has a mobile hamburger trigger on < 768px screens
function ensureMobileMenuTriggerInHeader() {
  const headerContainer = document.querySelector('header > div');
  if (!headerContainer) return;
  if (headerContainer.querySelector('.open-mobile-menu-btn')) return;

  const firstLink = headerContainer.querySelector('a[href*="index.html"], a[href="/"]');
  if (!firstLink) return;

  const leftWrap = document.createElement('div');
  leftWrap.className = 'flex items-center gap-2';
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.className = 'open-mobile-menu-btn md:hidden p-2 -ml-2 text-foreground hover:text-primary transition cursor-pointer';
  btn.setAttribute('aria-label', 'Open Navigation Menu');
  btn.innerHTML = `<svg class="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8" d="M4 6h16M4 12h16M4 18h16"/></svg>`;

  headerContainer.insertBefore(leftWrap, firstLink);
  leftWrap.appendChild(btn);
  leftWrap.appendChild(firstLink);
}

// ================= Global Shell: Announcement, Drawers, Modals =================
function injectGlobalStorefrontShell() {
  ensureMobileMenuTriggerInHeader();
  if (document.getElementById('naari-storefront-shell')) return;

  const shell = document.createElement('div');
  shell.id = 'naari-storefront-shell';
  shell.innerHTML = `
    <!-- Mobile Navigation Drawer (Accessible on < 768px) -->
    <div id="mobile-nav-drawer-overlay" class="fixed inset-0 z-50 invisible opacity-0 transition-opacity duration-300 md:hidden">
      <div id="mobile-nav-drawer-backdrop" class="drawer-backdrop absolute inset-0"></div>
      <nav id="mobile-nav-drawer-panel" aria-label="Mobile Navigation" class="drawer-panel absolute top-0 left-0 h-full w-[85vw] max-w-xs bg-card shadow-2xl flex flex-col transform -translate-x-full transition-transform duration-300">
        <div class="flex items-center justify-between border-b border-border px-5 py-4 bg-background/95">
          <a href="index.html" class="flex items-center gap-2.5">
            <img src="logo.png" alt="Matra Naari" class="h-9 w-9 object-contain" onerror="this.style.display='none'"/>
            <div class="leading-none">
              <div class="font-display text-lg tracking-[0.18em] font-semibold text-primary">MATRA NAARI</div>
              <div class="font-hand text-xs text-muted-foreground -mt-0.5">kesar obligations</div>
            </div>
          </a>
          <button type="button" id="close-mobile-nav-btn" class="p-2 text-muted-foreground hover:text-primary transition cursor-pointer" aria-label="Close Menu">
            <svg class="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
          </button>
        </div>

        <div class="flex-1 overflow-y-auto px-5 py-4 space-y-5">
          <div class="space-y-1">
            <p class="text-[10px] uppercase tracking-[0.2em] text-muted-foreground font-semibold mb-2">Explore Store</p>
            <a href="index.html" class="flex items-center justify-between py-2.5 text-sm font-medium border-b border-border/50 hover:text-primary">Home <span>→</span></a>
            <a href="shop.html" class="flex items-center justify-between py-2.5 text-sm font-semibold text-primary border-b border-border/50">All Kurtis Collection <span>→</span></a>
            <a href="shop.html?sort=newest" class="flex items-center justify-between py-2.5 text-sm font-medium border-b border-border/50 hover:text-primary">New Arrivals <span class="text-[10px] bg-primary/10 text-primary px-1.5 py-0.5 rounded">NEW</span></a>
            <a href="shop.html?sort=bestseller" class="flex items-center justify-between py-2.5 text-sm font-medium border-b border-border/50 hover:text-primary">Bestsellers <span>★</span></a>
          </div>

          <div>
            <p class="text-[10px] uppercase tracking-[0.2em] text-muted-foreground font-semibold mb-2.5">Shop By Silhouette</p>
            <div class="grid grid-cols-2 gap-2 text-xs">
              <a href="shop.html?category=Straight Cut" class="border border-border bg-background/60 px-3 py-2 rounded-xs hover:border-primary hover:text-primary transition">Straight Cut</a>
              <a href="shop.html?category=Anarkali" class="border border-border bg-background/60 px-3 py-2 rounded-xs hover:border-primary hover:text-primary transition">Anarkali</a>
              <a href="shop.html?category=A-Line" class="border border-border bg-background/60 px-3 py-2 rounded-xs hover:border-primary hover:text-primary transition">A-Line</a>
              <a href="shop.html?category=Co-ord Set" class="border border-border bg-background/60 px-3 py-2 rounded-xs hover:border-primary hover:text-primary transition">Co-ord Sets</a>
              <a href="shop.html?category=Short Kurti" class="border border-border bg-background/60 px-3 py-2 rounded-xs hover:border-primary hover:text-primary transition">Short Kurtis</a>
              <a href="shop.html?category=Angrakha" class="border border-border bg-background/60 px-3 py-2 rounded-xs hover:border-primary hover:text-primary transition">Angrakha</a>
              <a href="shop.html?category=Kaftan" class="border border-border bg-background/60 px-3 py-2 rounded-xs hover:border-primary hover:text-primary transition">Kaftan</a>
            </div>
          </div>

          <div class="space-y-1 pt-2 border-t border-border">
            <p class="text-[10px] uppercase tracking-[0.2em] text-muted-foreground font-semibold mb-2">Customer Care & Account</p>
            <a href="account.html" class="flex items-center justify-between py-2 text-sm hover:text-primary">My Account & Orders <span>→</span></a>
            <a href="cart.html" class="flex items-center justify-between py-2 text-sm hover:text-primary">Shopping Bag <span>→</span></a>
            <a href="story.html" class="flex items-center justify-between py-2 text-sm hover:text-primary">Our Craft & Story <span>→</span></a>
            <a href="contact.html" class="flex items-center justify-between py-2 text-sm hover:text-primary">Contact & Support <span>→</span></a>
          </div>
        </div>

        <div class="border-t border-border p-4 bg-background/90 text-xs text-muted-foreground space-y-1">
          <p class="font-semibold text-foreground">Need Styling or Order Help?</p>
          <p>Call / WhatsApp: <a href="tel:+918849366915" class="text-primary underline">+91 88493 66915</a></p>
        </div>
      </nav>
    </div>

    <!-- Slide-over Cart Drawer -->
    <div id="cart-drawer-overlay" class="fixed inset-0 z-50 invisible opacity-0 transition-opacity duration-300">
      <div id="cart-drawer-backdrop" class="drawer-backdrop absolute inset-0"></div>
      <div id="cart-drawer-panel" class="drawer-panel absolute top-0 right-0 h-full w-full max-w-md bg-card shadow-2xl flex flex-col transform translate-x-full transition-transform duration-300">
        <!-- Drawer Header -->
        <div class="flex items-center justify-between border-b border-border/80 px-5 py-4 bg-background/90">
          <div class="flex items-center gap-2">
            <span class="font-display text-2xl font-semibold text-primary">Your Bag</span>
            <span class="bag-count-badge flex h-5 min-w-[20px] items-center justify-center rounded-full bg-primary px-1.5 text-[11px] font-bold text-primary-foreground font-sans">0</span>
          </div>
          <button type="button" id="close-cart-drawer-btn" class="p-2 text-muted-foreground hover:text-primary transition cursor-pointer" aria-label="Close Bag">
            <svg class="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
          </button>
        </div>

        <!-- Free Shipping Progress Bar -->
        <div id="drawer-shipping-meter" class="border-b border-border/60 bg-primary/5 px-5 py-2.5 text-xs text-center font-hand">
          <p id="drawer-shipping-text" class="text-foreground">Add ₹999 for Free Express Delivery ✿</p>
          <div class="mt-1.5 h-1.5 w-full overflow-hidden rounded-full bg-border">
            <div id="drawer-shipping-bar" class="progress-bar-fill h-full bg-primary" style="width: 0%;"></div>
          </div>
        </div>

        <!-- Cart Items List Container -->
        <div id="cart-drawer-items" class="flex-1 overflow-y-auto p-4 space-y-3">
          <!-- Populated by JavaScript -->
        </div>

        <!-- Drawer Footer & Coupon Input -->
        <div id="cart-drawer-footer" class="border-t border-border bg-background/90 p-5 space-y-4">
          <!-- Coupon Box -->
          <div class="space-y-2">
            <form id="drawer-coupon-form" class="flex gap-2">
              <input
                id="drawer-coupon-input"
                type="text"
                placeholder="Promo Code (e.g. NAARI10)"
                class="min-w-0 flex-1 border border-border bg-card px-3 py-2 text-xs uppercase tracking-wider outline-none focus:border-primary font-mono"
              />
              <button
                type="submit"
                class="bg-primary px-4 py-2 text-xs uppercase tracking-wider text-primary-foreground hover:opacity-90 transition cursor-pointer"
              >
                Apply
              </button>
            </form>
            <div id="drawer-coupon-status" class="text-xs"></div>
          </div>

          <!-- Price Breakdown -->
          <div class="space-y-1.5 text-sm">
            <div class="flex justify-between text-muted-foreground">
              <span>Bag Subtotal</span>
              <span id="drawer-subtotal" class="font-display text-base text-foreground">₹0</span>
            </div>
            <div id="drawer-discount-row" class="hidden justify-between items-center text-emerald-800 font-medium">
              <span class="flex items-center gap-1.5">
                Coupon (<span id="drawer-coupon-name"></span>)
                <button type="button" id="drawer-remove-coupon-btn" class="text-[10px] text-destructive underline cursor-pointer">Remove</button>
              </span>
              <span id="drawer-discount">-₹0</span>
            </div>
            <div class="flex justify-between text-muted-foreground">
              <span>Estimated Shipping</span>
              <span id="drawer-shipping" class="text-xs uppercase tracking-wider text-primary font-semibold">FREE</span>
            </div>
            <div class="flex items-center justify-between border-t border-border pt-2 text-base font-semibold">
              <span class="font-hand text-lg">Total</span>
              <span id="drawer-total" class="font-display text-xl text-primary">₹0</span>
            </div>
          </div>

          <!-- Checkout CTA -->
          <div class="grid grid-cols-2 gap-2 pt-1">
            <a
              href="cart.html"
              class="border border-primary py-3 text-center text-xs uppercase tracking-[0.15em] text-primary hover:bg-primary/5 transition font-medium"
            >
              View Bag
            </a>
            <a
              href="checkout.html"
              class="bg-primary py-3 text-center text-xs uppercase tracking-[0.15em] text-primary-foreground hover:opacity-90 transition font-medium shadow"
            >
              Checkout →
            </a>
          </div>
          <p class="text-center text-[11px] text-muted-foreground font-hand">✿ 100% Secure Checkout · COD Available Across India</p>
        </div>
      </div>
    </div>

    <!-- Wishlist Drawer -->
    <div id="wishlist-drawer-overlay" class="fixed inset-0 z-50 invisible opacity-0 transition-opacity duration-300">
      <div id="wishlist-drawer-backdrop" class="drawer-backdrop absolute inset-0"></div>
      <div id="wishlist-drawer-panel" class="drawer-panel absolute top-0 right-0 h-full w-full max-w-md bg-card shadow-2xl flex flex-col transform translate-x-full transition-transform duration-300">
        <div class="flex items-center justify-between border-b border-border/80 px-5 py-4 bg-background/90">
          <div class="flex items-center gap-2">
            <span class="font-display text-2xl font-semibold text-primary">Saved Kurtis</span>
            <span class="wishlist-count-badge flex h-5 min-w-[20px] items-center justify-center rounded-full bg-primary/20 px-1.5 text-[11px] font-bold text-primary font-sans">0</span>
          </div>
          <button type="button" id="close-wishlist-drawer-btn" class="p-2 text-muted-foreground hover:text-primary transition cursor-pointer" aria-label="Close Wishlist">
            <svg class="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
          </button>
        </div>
        <div id="wishlist-drawer-items" class="flex-1 overflow-y-auto p-4 space-y-3">
          <!-- Populated by JavaScript -->
        </div>
        <div class="border-t border-border p-4 bg-background/90 text-center">
          <a href="shop.html" class="inline-block font-hand text-primary underline">Discover more kurtis in our collection →</a>
        </div>
      </div>
    </div>

    <!-- Live Search Modal -->
    <div id="search-modal-overlay" class="fixed inset-0 z-50 invisible opacity-0 transition-opacity duration-200 flex items-start justify-center pt-16 px-4">
      <div id="search-modal-backdrop" class="drawer-backdrop absolute inset-0"></div>
      <div class="modal-enter relative w-full max-w-2xl bg-card border border-border shadow-2xl overflow-hidden rounded-sm z-10">
        <div class="flex items-center border-b border-border px-4 py-3 bg-background">
          <svg class="h-5 w-5 text-muted-foreground mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>
          <input
            id="global-search-input"
            type="text"
            placeholder="Search kurtis by style, silhouette, fabric, occasion..."
            class="w-full bg-transparent font-sans text-base outline-none text-foreground placeholder:text-muted-foreground"
            autocomplete="off"
          />
          <button type="button" id="close-search-modal-btn" class="p-1.5 text-muted-foreground hover:text-primary transition cursor-pointer">
            ✕
          </button>
        </div>
        <!-- Quick search categories -->
        <div class="bg-background/50 px-4 py-2 border-b border-border/50 flex flex-wrap gap-1.5 text-xs">
          <span class="text-muted-foreground font-hand mr-1">popular:</span>
          <a href="shop.html?category=Anarkali" class="hover:text-primary transition underline">Anarkali</a> ·
          <a href="shop.html?category=Straight Cut" class="hover:text-primary transition underline">Straight Cut</a> ·
          <a href="shop.html?category=Co-ord Set" class="hover:text-primary transition underline">Co-ords</a> ·
          <a href="shop.html?category=Short Kurti" class="hover:text-primary transition underline">Short Kurtis</a> ·
          <a href="shop.html?category=Angrakha" class="hover:text-primary transition underline">Angrakha</a>
        </div>
        <!-- Live search results container -->
        <div id="global-search-results" class="max-h-[60vh] overflow-y-auto p-4 space-y-2">
          <p class="text-center text-sm text-muted-foreground py-6 font-hand">Type above to search our handcrafted collection ✿</p>
        </div>
      </div>
    </div>

    <!-- Customer Auth Modal (Login / Register) -->
    <div id="auth-modal-overlay" class="fixed inset-0 z-50 invisible opacity-0 transition-opacity duration-200 flex items-center justify-center p-4">
      <div id="auth-modal-backdrop" class="drawer-backdrop absolute inset-0"></div>
      <div class="modal-enter relative w-full max-w-md bg-card border border-border shadow-2xl p-6 sm:p-8 z-10">
        <button type="button" id="close-auth-modal-btn" class="absolute top-4 right-4 text-muted-foreground hover:text-primary transition cursor-pointer">✕</button>
        
        <div class="text-center mb-6">
          <p class="font-hand text-lg text-primary">welcome to</p>
          <h2 class="font-display text-3xl font-semibold">Matra Naari</h2>
          <p class="text-xs text-muted-foreground mt-1">Sign in to track orders, save addresses, and view your bag.</p>
        </div>

        <!-- Auth Tabs -->
        <div class="grid grid-cols-2 border-b border-border mb-6">
          <button type="button" id="auth-tab-login" class="pb-2 text-sm font-semibold border-b-2 border-primary text-primary cursor-pointer">Sign In</button>
          <button type="button" id="auth-tab-register" class="pb-2 text-sm font-semibold border-b-2 border-transparent text-muted-foreground hover:text-foreground cursor-pointer">Register</button>
        </div>

        <!-- Login Form -->
        <form id="auth-login-form" class="space-y-4">
          <div>
            <label class="block text-xs uppercase tracking-wider text-muted-foreground mb-1">Email Address</label>
            <input type="email" id="login-email" required placeholder="you@example.com" class="w-full border border-border bg-background px-3 py-2 text-sm outline-none focus:border-primary"/>
          </div>
          <div>
            <label class="block text-xs uppercase tracking-wider text-muted-foreground mb-1">Password</label>
            <input type="password" id="login-password" required placeholder="••••••••" class="w-full border border-border bg-background px-3 py-2 text-sm outline-none focus:border-primary"/>
          </div>
          <div id="login-error-msg" class="text-xs text-destructive hidden"></div>
          <button type="submit" class="w-full bg-primary py-3 text-xs uppercase tracking-[0.2em] text-primary-foreground hover:opacity-90 transition font-medium cursor-pointer">
            Sign In
          </button>
        </form>

        <!-- Register Form -->
        <form id="auth-register-form" class="space-y-4 hidden">
          <div>
            <label class="block text-xs uppercase tracking-wider text-muted-foreground mb-1">Full Name</label>
            <input type="text" id="reg-name" required placeholder="Ananya Sharma" class="w-full border border-border bg-background px-3 py-2 text-sm outline-none focus:border-primary"/>
          </div>
          <div>
            <label class="block text-xs uppercase tracking-wider text-muted-foreground mb-1">Email Address</label>
            <input type="email" id="reg-email" required placeholder="ananya@example.com" class="w-full border border-border bg-background px-3 py-2 text-sm outline-none focus:border-primary"/>
          </div>
          <div>
            <label class="block text-xs uppercase tracking-wider text-muted-foreground mb-1">Mobile Phone (10 digits)</label>
            <input type="tel" id="reg-phone" maxlength="10" required placeholder="9876543210" class="w-full border border-border bg-background px-3 py-2 text-sm outline-none focus:border-primary"/>
          </div>
          <div>
            <label class="block text-xs uppercase tracking-wider text-muted-foreground mb-1">Create Password</label>
            <input type="password" id="reg-password" minlength="6" required placeholder="At least 6 characters" class="w-full border border-border bg-background px-3 py-2 text-sm outline-none focus:border-primary"/>
          </div>
          <div id="reg-error-msg" class="text-xs text-destructive hidden"></div>
          <button type="submit" class="w-full bg-primary py-3 text-xs uppercase tracking-[0.2em] text-primary-foreground hover:opacity-90 transition font-medium cursor-pointer">
            Create Account
          </button>
        </form>
      </div>
    </div>
  `;

  document.body.appendChild(shell);
  attachGlobalShellEvents();
}

// ================= Drawer & Modal Handlers =================
function openMobileNavDrawer() {
  const overlay = document.getElementById('mobile-nav-drawer-overlay');
  const panel = document.getElementById('mobile-nav-drawer-panel');
  if (!overlay || !panel) return;
  overlay.classList.remove('invisible', 'opacity-0');
  overlay.classList.add('opacity-100');
  panel.classList.remove('-translate-x-full');
  panel.classList.add('translate-x-0');
  document.body.style.overflow = 'hidden';
}

function closeMobileNavDrawer() {
  const overlay = document.getElementById('mobile-nav-drawer-overlay');
  const panel = document.getElementById('mobile-nav-drawer-panel');
  if (!overlay || !panel) return;
  panel.classList.remove('translate-x-0');
  panel.classList.add('-translate-x-full');
  overlay.classList.remove('opacity-100');
  overlay.classList.add('opacity-0');
  setTimeout(() => {
    overlay.classList.add('invisible');
    document.body.style.overflow = '';
  }, 300);
}

function openCartDrawer() {
  const overlay = document.getElementById('cart-drawer-overlay');
  const panel = document.getElementById('cart-drawer-panel');
  if (!overlay || !panel) return;
  renderCartDrawerContent();
  overlay.classList.remove('invisible', 'opacity-0');
  overlay.classList.add('opacity-100');
  panel.classList.remove('translate-x-full');
  panel.classList.add('translate-x-0');
  document.body.style.overflow = 'hidden';
}

function closeCartDrawer() {
  const overlay = document.getElementById('cart-drawer-overlay');
  const panel = document.getElementById('cart-drawer-panel');
  if (!overlay || !panel) return;
  panel.classList.remove('translate-x-0');
  panel.classList.add('translate-x-full');
  overlay.classList.remove('opacity-100');
  overlay.classList.add('opacity-0');
  setTimeout(() => {
    overlay.classList.add('invisible');
    document.body.style.overflow = '';
  }, 300);
}

function openWishlistDrawer() {
  const overlay = document.getElementById('wishlist-drawer-overlay');
  const panel = document.getElementById('wishlist-drawer-panel');
  if (!overlay || !panel) return;
  renderWishlistDrawerContent();
  overlay.classList.remove('invisible', 'opacity-0');
  overlay.classList.add('opacity-100');
  panel.classList.remove('translate-x-full');
  panel.classList.add('translate-x-0');
  document.body.style.overflow = 'hidden';
}

function closeWishlistDrawer() {
  const overlay = document.getElementById('wishlist-drawer-overlay');
  const panel = document.getElementById('wishlist-drawer-panel');
  if (!overlay || !panel) return;
  panel.classList.remove('translate-x-0');
  panel.classList.add('translate-x-full');
  overlay.classList.remove('opacity-100');
  overlay.classList.add('opacity-0');
  setTimeout(() => {
    overlay.classList.add('invisible');
    document.body.style.overflow = '';
  }, 300);
}

function openSearchModal() {
  const overlay = document.getElementById('search-modal-overlay');
  const input = document.getElementById('global-search-input');
  if (!overlay) return;
  overlay.classList.remove('invisible', 'opacity-0');
  overlay.classList.add('opacity-100');
  document.body.style.overflow = 'hidden';
  if (input) {
    setTimeout(() => input.focus(), 100);
  }
}

function closeSearchModal() {
  const overlay = document.getElementById('search-modal-overlay');
  if (!overlay) return;
  overlay.classList.remove('opacity-100');
  overlay.classList.add('opacity-0');
  setTimeout(() => {
    overlay.classList.add('invisible');
    document.body.style.overflow = '';
  }, 200);
}

function openAuthModal(defaultTab = 'login') {
  const overlay = document.getElementById('auth-modal-overlay');
  if (!overlay) return;
  switchAuthTab(defaultTab);
  overlay.classList.remove('invisible', 'opacity-0');
  overlay.classList.add('opacity-100');
  document.body.style.overflow = 'hidden';
}

function closeAuthModal() {
  const overlay = document.getElementById('auth-modal-overlay');
  if (!overlay) return;
  overlay.classList.remove('opacity-100');
  overlay.classList.add('opacity-0');
  setTimeout(() => {
    overlay.classList.add('invisible');
    document.body.style.overflow = '';
  }, 200);
}

function switchAuthTab(tab) {
  const loginBtn = document.getElementById('auth-tab-login');
  const regBtn = document.getElementById('auth-tab-register');
  const loginForm = document.getElementById('auth-login-form');
  const regForm = document.getElementById('auth-register-form');
  if (!loginBtn || !regBtn) return;

  if (tab === 'login') {
    loginBtn.className = 'pb-2 text-sm font-semibold border-b-2 border-primary text-primary cursor-pointer';
    regBtn.className = 'pb-2 text-sm font-semibold border-b-2 border-transparent text-muted-foreground hover:text-foreground cursor-pointer';
    loginForm.classList.remove('hidden');
    regForm.classList.add('hidden');
  } else {
    regBtn.className = 'pb-2 text-sm font-semibold border-b-2 border-primary text-primary cursor-pointer';
    loginBtn.className = 'pb-2 text-sm font-semibold border-b-2 border-transparent text-muted-foreground hover:text-foreground cursor-pointer';
    regForm.classList.remove('hidden');
    loginForm.classList.add('hidden');
  }
}

// ================= Render Cart Drawer Content =================
function renderCartDrawerContent() {
  const container = document.getElementById('cart-drawer-items');
  const subtotalEl = document.getElementById('drawer-subtotal');
  const totalEl = document.getElementById('drawer-total');
  const discRow = document.getElementById('drawer-discount-row');
  const discEl = document.getElementById('drawer-discount');
  const couponNameEl = document.getElementById('drawer-coupon-name');
  const shippingEl = document.getElementById('drawer-shipping');
  const meterText = document.getElementById('drawer-shipping-text');
  const meterBar = document.getElementById('drawer-shipping-bar');
  if (!container) return;

  const cart = getCart();
  const subtotal = getCartSubtotal();
  const activeCoupon = getActiveCoupon();

  const freeThreshold = Number(window.NAARI_STORE_SETTINGS?.free_shipping_threshold ?? 999);
  const stdShippingFee = Number(window.NAARI_STORE_SETTINGS?.shipping_fee ?? 99);

  if (subtotal >= freeThreshold && cart.length > 0) {
    if (meterText) meterText.innerHTML = '🎉 You have unlocked <strong>FREE Express Delivery</strong> across India!';
    if (meterBar) meterBar.style.width = '100%';
    if (shippingEl) shippingEl.textContent = 'FREE';
  } else {
    const diff = Math.max(0, freeThreshold - subtotal);
    if (meterText) meterText.innerHTML = `Add <strong>${formatPrice(diff)}</strong> more to get <strong>FREE Delivery</strong> ✿`;
    const pct = freeThreshold > 0 ? Math.min(100, Math.round((subtotal / freeThreshold) * 100)) : 100;
    if (meterBar) meterBar.style.width = `${pct}%`;
    if (shippingEl) shippingEl.textContent = cart.length > 0 ? formatPrice(stdShippingFee) : 'FREE';
  }

  if (cart.length === 0) {
    container.innerHTML = `
      <div class="py-16 text-center">
        <p class="font-hand text-xl text-muted-foreground">Your shopping bag is empty.</p>
        <p class="text-xs text-muted-foreground mt-1">Explore our kurtis crafted for everyday elegance.</p>
        <a href="shop.html" class="mt-5 inline-block bg-primary px-6 py-2.5 text-xs uppercase tracking-widest text-primary-foreground hover:opacity-90 transition font-medium">
          Explore Kurtis
        </a>
      </div>
    `;
    if (subtotalEl) subtotalEl.textContent = formatPrice(0);
    if (totalEl) totalEl.textContent = formatPrice(0);
    if (discRow) discRow.classList.add('hidden');
    return;
  }

  // Calculate discount if coupon active
  let discountAmount = 0;
  if (activeCoupon && activeCoupon.code) {
    const minOrd = Number(activeCoupon.min_order_value || 0);
    if (subtotal >= minOrd) {
      if (activeCoupon.discount_type === 'percentage') {
        discountAmount = Math.round(subtotal * (activeCoupon.discount_value / 100));
        if (activeCoupon.max_discount && discountAmount > activeCoupon.max_discount) {
          discountAmount = activeCoupon.max_discount;
        }
      } else {
        discountAmount = Math.min(activeCoupon.discount_value, subtotal);
      }
    }
  }

  const shipping = subtotal >= freeThreshold ? 0 : stdShippingFee;
  const finalTotal = Math.max(0, subtotal - discountAmount + shipping);

  if (subtotalEl) subtotalEl.textContent = formatPrice(subtotal);
  if (totalEl) totalEl.textContent = formatPrice(finalTotal);

  if (discountAmount > 0 && activeCoupon) {
    if (discRow) {
      discRow.classList.remove('hidden');
      discRow.classList.add('flex');
    }
    if (couponNameEl) couponNameEl.textContent = activeCoupon.code;
    if (discEl) discEl.textContent = `-${formatPrice(discountAmount)}`;
  } else {
    if (discRow) {
      discRow.classList.add('hidden');
      discRow.classList.remove('flex');
    }
  }

  container.innerHTML = cart.map(item => `
    <div class="flex gap-3 bg-card/60 p-3 ring-1 ring-border rounded-sm relative">
      <img src="${item.image}" alt="${item.name}" onerror="this.onerror=null;this.src='assets/hero.jpg';" class="h-20 w-16 object-cover rounded-xs shrink-0"/>
      <div class="min-w-0 flex-1 flex flex-col justify-between">
        <div class="pr-5">
          <a href="product.html?id=${item.id}" class="truncate font-display text-base font-semibold hover:text-primary transition block">${item.name}</a>
          <p class="text-xs text-muted-foreground">${item.color} · Size: <span class="text-foreground font-medium">${item.size}</span></p>
        </div>
        <div class="flex items-center justify-between mt-2">
          <!-- Quantity Controls -->
          <div class="flex items-center border border-border">
            <button type="button" class="drawer-qty-dec h-7 w-7 flex items-center justify-center hover:text-primary cursor-pointer text-xs" data-key="${item.key}" aria-label="Decrease quantity">−</button>
            <span class="w-7 text-center text-xs tabular-nums font-semibold">${item.qty}</span>
            <button type="button" class="drawer-qty-inc h-7 w-7 flex items-center justify-center hover:text-primary cursor-pointer text-xs" data-key="${item.key}" aria-label="Increase quantity">+</button>
          </div>
          <div class="text-right">
            <span class="font-display text-base font-semibold text-primary">${formatPrice(item.price * item.qty)}</span>
          </div>
        </div>
      </div>
      <button type="button" class="drawer-remove-item absolute top-2 right-2 text-muted-foreground hover:text-destructive text-xs cursor-pointer p-1.5" data-key="${item.key}" title="Remove item" aria-label="Remove item">
        ✕
      </button>
    </div>
  `).join('');

  // Attach button events
  container.querySelectorAll('.drawer-qty-dec').forEach(btn => {
    btn.addEventListener('click', () => {
      const key = btn.dataset.key;
      const item = cart.find(i => i.key === key);
      if (item) updateCartQty(key, item.qty - 1);
    });
  });

  container.querySelectorAll('.drawer-qty-inc').forEach(btn => {
    btn.addEventListener('click', () => {
      const key = btn.dataset.key;
      const item = cart.find(i => i.key === key);
      if (item) updateCartQty(key, item.qty + 1);
    });
  });

  container.querySelectorAll('.drawer-remove-item').forEach(btn => {
    btn.addEventListener('click', () => {
      removeCartItem(btn.dataset.key);
    });
  });
}

// ================= Render Wishlist Drawer Content =================
function renderWishlistDrawerContent() {
  const container = document.getElementById('wishlist-drawer-items');
  if (!container) return;
  const list = getWishlist();

  if (list.length === 0) {
    container.innerHTML = `
      <div class="py-16 text-center">
        <p class="font-hand text-xl text-muted-foreground">Your wishlist is empty.</p>
        <p class="text-xs text-muted-foreground mt-1">Tap the heart icon on any kurti to save your favourites.</p>
        <a href="shop.html" class="mt-5 inline-block bg-primary px-6 py-2.5 text-xs uppercase tracking-widest text-primary-foreground hover:opacity-90 transition font-medium">
          Explore Kurtis
        </a>
      </div>
    `;
    return;
  }

  container.innerHTML = list.map(item => `
    <div class="flex gap-3 bg-card/60 p-3 ring-1 ring-border rounded-sm relative">
      <img src="${item.image}" alt="${item.name}" onerror="this.onerror=null;this.src='assets/hero.jpg';" class="h-24 w-18 object-cover rounded-xs shrink-0"/>
      <div class="min-w-0 flex-1 flex flex-col justify-between">
        <div>
          <a href="product.html?id=${item.id}" class="truncate font-display text-base font-semibold hover:text-primary transition block">${item.name}</a>
          <p class="text-xs text-muted-foreground">${item.category}</p>
          <div class="mt-1 flex items-baseline gap-2">
            <span class="font-display text-base font-semibold text-primary">${formatPrice(item.price)}</span>
            ${item.mrp ? `<span class="text-xs line-through text-muted-foreground">${formatPrice(item.mrp)}</span>` : ''}
          </div>
        </div>
        <div class="mt-2 flex gap-2">
          <button type="button" class="wishlist-move-to-bag bg-primary px-3 py-1.5 text-xs text-primary-foreground hover:opacity-90 uppercase tracking-wider transition cursor-pointer" data-id="${item.id}">
            Add to Bag
          </button>
          <button type="button" class="wishlist-remove-btn text-xs text-muted-foreground hover:text-destructive underline cursor-pointer" data-id="${item.id}">
            Remove
          </button>
        </div>
      </div>
    </div>
  `).join('');

  container.querySelectorAll('.wishlist-move-to-bag').forEach(btn => {
    btn.addEventListener('click', () => {
      const pid = btn.dataset.id;
      const prod = PRODUCTS.find(p => p.id === pid) || list.find(i => i.id === pid);
      if (prod) {
        addToCart({
          id: prod.id,
          name: prod.name,
          color: prod.colors ? prod.colors[0]?.name : 'Standard',
          size: prod.sizes ? prod.sizes[0] : 'Free Size',
          price: prod.price,
          image: prod.image || prod.relativeImage,
          qty: 1
        });
        closeWishlistDrawer();
      }
    });
  });

  container.querySelectorAll('.wishlist-remove-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const pid = btn.dataset.id;
      let wlist = getWishlist();
      wlist = wlist.filter(i => i.id !== pid);
      saveWishlist(wlist);
    });
  });
}

// ================= Global Shell Event Listeners =================
function attachGlobalShellEvents() {
  // Mobile menu triggers
  document.querySelectorAll('.open-mobile-menu-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      openMobileNavDrawer();
    });
  });

  const closeMobNavBtn = document.getElementById('close-mobile-nav-btn');
  const mobNavBackdrop = document.getElementById('mobile-nav-drawer-backdrop');
  if (closeMobNavBtn) closeMobNavBtn.addEventListener('click', closeMobileNavDrawer);
  if (mobNavBackdrop) mobNavBackdrop.addEventListener('click', closeMobileNavDrawer);

  // Cart drawer triggers
  document.querySelectorAll('.open-cart-drawer-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      openCartDrawer();
    });
  });

  const closeCartBtn = document.getElementById('close-cart-drawer-btn');
  const cartBackdrop = document.getElementById('cart-drawer-backdrop');
  if (closeCartBtn) closeCartBtn.addEventListener('click', closeCartDrawer);
  if (cartBackdrop) cartBackdrop.addEventListener('click', closeCartDrawer);

  // Wishlist drawer triggers
  document.querySelectorAll('.open-wishlist-drawer-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      openWishlistDrawer();
    });
  });

  const closeWishlistBtn = document.getElementById('close-wishlist-drawer-btn');
  const wishlistBackdrop = document.getElementById('wishlist-drawer-backdrop');
  if (closeWishlistBtn) closeWishlistBtn.addEventListener('click', closeWishlistDrawer);
  if (wishlistBackdrop) wishlistBackdrop.addEventListener('click', closeWishlistDrawer);

  // Search modal triggers
  document.querySelectorAll('.open-search-modal-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      openSearchModal();
    });
  });

  const closeSearchBtn = document.getElementById('close-search-modal-btn');
  const searchBackdrop = document.getElementById('search-modal-backdrop');
  if (closeSearchBtn) closeSearchBtn.addEventListener('click', closeSearchModal);
  if (searchBackdrop) searchBackdrop.addEventListener('click', closeSearchModal);

  // Keyboard shortcut: Cmd/Ctrl + K opens search
  document.addEventListener('keydown', (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
      e.preventDefault();
      openSearchModal();
    }
    if (e.key === 'Escape') {
      closeMobileNavDrawer();
      closeCartDrawer();
      closeWishlistDrawer();
      closeSearchModal();
      closeAuthModal();
    }
  });

  // Search input live filtering
  const searchInput = document.getElementById('global-search-input');
  const searchResults = document.getElementById('global-search-results');
  let searchDebounce;
  if (searchInput && searchResults) {
    searchInput.addEventListener('input', () => {
      clearTimeout(searchDebounce);
      const query = searchInput.value.trim().toLowerCase();
      if (!query) {
        searchResults.innerHTML = '<p class="text-center text-sm text-muted-foreground py-6 font-hand">Type above to search our handcrafted collection ✿</p>';
        return;
      }

      searchDebounce = setTimeout(async () => {
        searchResults.innerHTML = '<p class="text-center text-sm text-primary py-4 animate-pulse">Searching...</p>';
        try {
          const resp = await fetch(`${API_BASE}/api/products?search=${encodeURIComponent(query)}`);
          const data = await resp.json();
          const items = data.products || [];

          if (items.length === 0) {
            searchResults.innerHTML = `
              <div class="py-6 text-center text-sm text-muted-foreground">
                <p>No kurtis matching "${query}".</p>
                <a href="shop.html" class="mt-2 inline-block font-hand text-primary underline">View all kurtis →</a>
              </div>
            `;
            return;
          }

          searchResults.innerHTML = items.map(p => `
            <a href="product.html?id=${p.id}" class="flex items-center gap-3 p-2 hover:bg-primary/5 transition rounded-sm border border-transparent hover:border-border">
              <img src="${p.relative_image || p.image}" alt="${p.name}" onerror="this.onerror=null;this.src='assets/hero.jpg';" class="h-14 w-12 object-cover rounded-xs shrink-0"/>
              <div class="min-w-0 flex-1">
                <p class="truncate text-sm font-semibold">${p.name}</p>
                <p class="text-xs text-muted-foreground">${p.category} · ${p.fabric || 'Cotton'}</p>
                <div class="flex items-center gap-2 mt-0.5">
                  <span class="font-display text-sm font-semibold text-primary">${formatPrice(p.price)}</span>
                  ${p.mrp ? `<span class="text-[11px] line-through text-muted-foreground">${formatPrice(p.mrp)}</span>` : ''}
                  ${p.discountPercent ? `<span class="text-[10px] bg-primary/10 text-primary px-1 rounded">${p.discountPercent}% OFF</span>` : ''}
                </div>
              </div>
              <span class="text-xs text-primary font-hand shrink-0">view →</span>
            </a>
          `).join('');
        } catch (e) {
          searchResults.innerHTML = '<p class="text-center text-xs text-destructive py-4">Error loading results. Please try again.</p>';
        }
      }, 250);
    });
  }

  // Auth modal triggers
  document.querySelectorAll('.open-auth-modal-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      const userSession = getUserSession();
      if (userSession) {
        window.location.href = 'account.html';
      } else {
        openAuthModal('login');
      }
    });
  });

  const closeAuthBtn = document.getElementById('close-auth-modal-btn');
  const authBackdrop = document.getElementById('auth-modal-backdrop');
  if (closeAuthBtn) closeAuthBtn.addEventListener('click', closeAuthModal);
  if (authBackdrop) authBackdrop.addEventListener('click', closeAuthModal);

  const authTabLogin = document.getElementById('auth-tab-login');
  const authTabReg = document.getElementById('auth-tab-register');
  if (authTabLogin) authTabLogin.addEventListener('click', () => switchAuthTab('login'));
  if (authTabReg) authTabReg.addEventListener('click', () => switchAuthTab('register'));

  // Auth Forms Submission
  const loginForm = document.getElementById('auth-login-form');
  if (loginForm) {
    loginForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const errBox = document.getElementById('login-error-msg');
      errBox.classList.add('hidden');
      const email = document.getElementById('login-email').value.trim();
      const password = document.getElementById('login-password').value;

      try {
        const resp = await fetch(`${API_BASE}/api/auth/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password })
        });
        const data = await resp.json();
        if (data.ok) {
          setUserSession(data.token, data.user);
          getToast().success(`Welcome back, ${data.user.name}!`);
          closeAuthModal();
        } else {
          errBox.textContent = data.error || 'Login failed.';
          errBox.classList.remove('hidden');
        }
      } catch (err) {
        errBox.textContent = 'Network error. Please try again.';
        errBox.classList.remove('hidden');
      }
    });
  }

  const regForm = document.getElementById('auth-register-form');
  if (regForm) {
    regForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const errBox = document.getElementById('reg-error-msg');
      errBox.classList.add('hidden');
      const name = document.getElementById('reg-name').value.trim();
      const email = document.getElementById('reg-email').value.trim();
      const phone = document.getElementById('reg-phone').value.trim();
      const password = document.getElementById('reg-password').value;

      try {
        const resp = await fetch(`${API_BASE}/api/auth/register`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name, email, phone, password })
        });
        const data = await resp.json();
        if (data.ok) {
          setUserSession(data.token, data.user);
          getToast().success(`Welcome to Matra Naari, ${data.user.name}!`);
          closeAuthModal();
        } else {
          errBox.textContent = data.error || 'Registration failed.';
          errBox.classList.remove('hidden');
        }
      } catch (err) {
        errBox.textContent = 'Network error. Please try again.';
        errBox.classList.remove('hidden');
      }
    });
  }

  // Drawer Coupon Application & Removal
  const couponForm = document.getElementById('drawer-coupon-form');
  if (couponForm) {
    couponForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const input = document.getElementById('drawer-coupon-input');
      const statusBox = document.getElementById('drawer-coupon-status');
      const code = input.value.trim().toUpperCase();
      const subtotal = getCartSubtotal();

      if (!code) return;
      statusBox.innerHTML = '<span class="text-primary animate-pulse">Checking code...</span>';

      try {
        const resp = await fetch(`${API_BASE}/api/apply-coupon`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ code, subtotal, items: getCart() })
        });
        const data = await resp.json();
        if (data.ok) {
          setActiveCoupon(data);
          statusBox.innerHTML = `<span class="text-emerald-800 font-medium">✓ ${data.message}</span>`;
          getToast().success(data.message);
        } else {
          setActiveCoupon(null);
          statusBox.innerHTML = `<span class="text-destructive">${data.error}</span>`;
          getToast().error(data.error);
        }
      } catch (err) {
        statusBox.innerHTML = '<span class="text-destructive">Failed to validate coupon.</span>';
      }
    });
  }

  const removeCouponBtn = document.getElementById('drawer-remove-coupon-btn');
  if (removeCouponBtn) {
    removeCouponBtn.addEventListener('click', () => {
      setActiveCoupon(null);
      const statusBox = document.getElementById('drawer-coupon-status');
      const input = document.getElementById('drawer-coupon-input');
      if (statusBox) statusBox.innerHTML = '';
      if (input) input.value = '';
      getToast().info('Coupon removed.');
    });
  }
}

// ================= Initialize Announcement Bar & Store Banners =================
async function initAnnouncementBar() {
  const bar = document.getElementById('top-announcement-bar');

  let messages = [
    'FREE EXPRESS SHIPPING ON ORDERS ABOVE ₹999 ACROSS INDIA ✿',
    'EXTRA 10% OFF ON ORDERS ABOVE ₹999 | CODE: NAARI10',
    'HANDCRAFTED IN PURE COTTON & NATURAL FIBRES',
    'EASY 7-DAY HASSLE-FREE RETURNS & SIZE EXCHANGES'
  ];

  try {
    const res = await fetch(`${API_BASE}/api/banners`);
    const data = await res.json();
    if (data && data.ok) {
      window.NAARI_STORE_SETTINGS = {
        ...window.NAARI_STORE_SETTINGS,
        free_shipping_threshold: data.free_shipping_threshold ?? 999,
        shipping_fee: data.shipping_fee ?? 99,
        cod_enabled: data.cod_enabled ?? true,
        announcement_enabled: data.announcement_enabled ?? true,
        promo_banner_enabled: data.promo_banner_enabled ?? true,
        active_promo_coupon: data.active_promo_coupon || null
      };
      renderCartDrawerContent();
      window.dispatchEvent(new CustomEvent('naari:settingsLoaded', { detail: window.NAARI_STORE_SETTINGS }));

      // Handle configurable promo banner visibility across homepage/shop
      document.querySelectorAll('.naari-configurable-promo-banner').forEach(bannerEl => {
        if (!data.promo_banner_enabled || !data.active_promo_coupon) {
          bannerEl.classList.add('hidden');
        } else {
          bannerEl.classList.remove('hidden');
          const cp = data.active_promo_coupon;
          const codeEl = bannerEl.querySelector('.promo-coupon-code');
          const descEl = bannerEl.querySelector('.promo-coupon-desc');
          const copyBtn = bannerEl.querySelector('[data-copy-coupon]');
          if (codeEl) codeEl.textContent = cp.code;
          if (descEl && cp.description) descEl.textContent = cp.description;
          if (copyBtn) copyBtn.setAttribute('data-copy-coupon', cp.code);
        }
      });

      if (data.announcement_enabled === false || (Array.isArray(data.announcements) && data.announcements.length === 0)) {
        if (bar) bar.classList.add('hidden');
        return;
      }
      if (data.announcements && data.announcements.length > 0) {
        messages = data.announcements;
      }
    }
  } catch (e) {}

  if (!bar) return;
  bar.classList.remove('hidden');

  let idx = 0;
  const textEl = bar.querySelector('.announcement-text');
  if (textEl && messages.length > 0) {
    textEl.textContent = messages[0];
    if (messages.length > 1) {
      setInterval(() => {
        idx = (idx + 1) % messages.length;
        textEl.style.opacity = '0';
        setTimeout(() => {
          textEl.textContent = messages[idx];
          textEl.style.opacity = '1';
        }, 300);
      }, 4500);
    }
  }
}

// ================= Auto Initialization on Page Load =================
document.addEventListener('DOMContentLoaded', () => {
  injectGlobalStorefrontShell();
  updateHeaderBadges();
  updateWishlistHeartButtons();
  initAnnouncementBar();
});

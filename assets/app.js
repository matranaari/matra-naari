/**
 * Naari - Modern Kurtis Rooted in Craft
 * Core client application logic & state management
 */

// Store phone number (WhatsApp enquiry & orders)
const STORE_PHONE = '918849366915';
const STORE_PHONE_DISPLAY = '+91 88493 66915';
const IS_PHONE_CONFIGURED = /^\d{10,15}$/.test(STORE_PHONE) && !/^910+$/.test(STORE_PHONE);

// Product Catalog
const PRODUCTS = [
  {
    id: 'straight',
    name: 'Gulmohar Straight Kurti',
    category: 'Straight Cut',
    note: 'Everyday ease, block-printed by hand.',
    image: '/assets/hero.jpg',
    relativeImage: 'assets/hero.jpg',
    price: 1299,
    colors: [
      { name: 'Maroon', swatch: 'oklch(0.38 0.13 10)' },
      { name: 'Ivory', swatch: 'oklch(0.95 0.02 85)' },
      { name: 'Indigo', swatch: 'oklch(0.35 0.12 265)' }
    ],
    sizes: ['XS', 'S', 'M', 'L', 'XL', 'XXL']
  },
  {
    id: 'aline',
    name: 'Chandni A-Line Kurti',
    category: 'A-Line',
    note: 'A soft flare with delicate thread work.',
    image: '/assets/k-aline.jpg',
    relativeImage: 'assets/k-aline.jpg',
    price: 1499,
    colors: [
      { name: 'Ivory', swatch: 'oklch(0.95 0.02 85)' },
      { name: 'Blush', swatch: 'oklch(0.78 0.06 10)' }
    ],
    sizes: ['S', 'M', 'L', 'XL']
  },
  {
    id: 'anarkali',
    name: 'Genda Anarkali',
    category: 'Anarkali',
    note: 'Twirl-worthy, for every celebration.',
    image: '/assets/k-anarkali.jpg',
    relativeImage: 'assets/k-anarkali.jpg',
    price: 2499,
    soldOutSizes: ['XXL'],
    colors: [
      { name: 'Marigold', swatch: 'oklch(0.75 0.15 90)' },
      { name: 'Maroon', swatch: 'oklch(0.38 0.13 10)' },
      { name: 'Emerald', swatch: 'oklch(0.45 0.1 160)' },
      { name: 'Rani Pink', swatch: 'oklch(0.55 0.2 0)' }
    ],
    sizes: ['XS', 'S', 'M', 'L', 'XL', 'XXL']
  },
  {
    id: 'short',
    name: 'Neel Short Kurti',
    category: 'Short Kurti',
    note: 'Pair it with denims, own the day.',
    image: '/assets/k-short.jpg',
    relativeImage: 'assets/k-short.jpg',
    price: 899,
    colors: [
      { name: 'Indigo', swatch: 'oklch(0.35 0.12 265)' },
      { name: 'White', swatch: 'oklch(0.98 0 0)' },
      { name: 'Black', swatch: 'oklch(0.2 0 0)' }
    ],
    sizes: ['XS', 'S', 'M', 'L', 'XL']
  },
  {
    id: 'angrakha',
    name: 'Tulsi Angrakha',
    category: 'Angrakha',
    note: 'A wrap silhouette with a tasselled tie.',
    image: '/assets/k-angrakha.jpg',
    relativeImage: 'assets/k-angrakha.jpg',
    price: 1799,
    colors: [
      { name: 'Sage', swatch: 'oklch(0.65 0.05 140)' },
      { name: 'Ivory', swatch: 'oklch(0.95 0.02 85)' }
    ],
    sizes: ['S', 'M', 'L', 'XL', 'XXL']
  },
  {
    id: 'kaftan',
    name: 'Sandhya Kaftan Kurti',
    category: 'Kaftan',
    note: 'Breezy, roomy and endlessly easy.',
    image: '/assets/k-kaftan.jpg',
    relativeImage: 'assets/k-kaftan.jpg',
    price: 1599,
    colors: [
      { name: 'Rust', swatch: 'oklch(0.55 0.15 40)' },
      { name: 'Sand', swatch: 'oklch(0.85 0.05 75)' },
      { name: 'Olive', swatch: 'oklch(0.5 0.08 120)' }
    ],
    sizes: ['Free Size']
  },
  {
    id: 'coord',
    name: 'Gulabi Kurta Set',
    category: 'Co-ord Set',
    note: 'Kurti and pants, perfectly matched.',
    image: '/assets/k-coord.jpg',
    relativeImage: 'assets/k-coord.jpg',
    price: 2199,
    colors: [
      { name: 'Dusty Pink', swatch: 'oklch(0.72 0.07 10)' },
      { name: 'Powder Blue', swatch: 'oklch(0.8 0.05 240)' }
    ],
    sizes: ['XS', 'S', 'M', 'L', 'XL', 'XXL']
  }
];

const CATEGORIES = Array.from(new Set(PRODUCTS.map(p => p.category)));

function formatPrice(amount) {
  return '₹' + amount.toLocaleString('en-IN');
}

function isSizeAvailable(product, size) {
  return product.inStock !== false && product.sizes.includes(size) && !product.soldOutSizes?.includes(size);
}

function generateWhatsAppMessage(items) {
  const lines = items.map((item, idx) => `${idx + 1}. ${item.name} — ${item.color}, Size ${item.size}, Qty ${item.qty} = ${formatPrice(item.price * item.qty)}`);
  const total = items.reduce((sum, item) => sum + item.price * item.qty, 0);
  return `Hi Naari! I'd like to order:\n${lines.join('\n')}\nTotal: ${formatPrice(total)}`;
}

// ================= Toast Notification System =================
class ToastManager {
  constructor() {
    this.container = document.createElement('div');
    this.container.id = 'naari-toast-container';
    this.container.className = 'fixed bottom-4 right-4 z-50 flex flex-col gap-2 max-w-sm w-full px-4 pointer-events-none';
    document.body.appendChild(this.container);
  }

  show(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `pointer-events-auto transform transition-all duration-300 ease-out flex items-center gap-3 px-4 py-3 rounded shadow-lg text-sm font-sans ${
      type === 'error'
        ? 'bg-[#2A1810] text-[#FFB4AB] border border-[#93000A]/40'
        : 'bg-[#2E1E1C] text-[#F9EBEA] border border-[#6B2D31]/50'
    } translate-y-4 opacity-0`;

    const icon = type === 'error' ? '⚠ ' : '✿ ';
    toast.innerHTML = `<span class="shrink-0 text-base">${icon}</span><span class="flex-1">${message}</span>`;
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
}

let toast;
function getToast() {
  if (!toast) toast = new ToastManager();
  return toast;
}

// ================= Cart State Management =================
const CART_STORAGE_KEY = 'naari_cart_v1';

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
  updateHeaderBagCount();
}

function addToCart(item) {
  const cart = getCart();
  const key = `${item.id}-${item.color}-${item.size}`;
  const existing = cart.find(i => i.key === key);
  if (existing) {
    existing.qty += item.qty;
  } else {
    cart.push({ ...item, key });
  }
  saveCart(cart);
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
}

function getCartCount() {
  const cart = getCart();
  return cart.reduce((sum, item) => sum + item.qty, 0);
}

function getCartTotal() {
  const cart = getCart();
  return cart.reduce((sum, item) => sum + item.price * item.qty, 0);
}

function updateHeaderBagCount() {
  const count = getCartCount();
  const badges = document.querySelectorAll('.bag-count-badge');
  badges.forEach(b => {
    b.textContent = count;
  });
}

// Detect image path based on current path depth
function resolvePath(path) {
  if (path.startsWith('/')) {
    // If running under file:// or relative directory, strip leading slash
    if (window.location.protocol === 'file:' || window.location.pathname.includes('/shop/') || window.location.pathname.includes('/story/') || window.location.pathname.includes('/contact/') || window.location.pathname.includes('/cart/')) {
      const depth = (window.location.pathname.match(/\//g) || []).length;
      if (window.location.pathname.includes('/shop/') || window.location.pathname.includes('/story/') || window.location.pathname.includes('/contact/') || window.location.pathname.includes('/cart/')) {
        return '..' + path;
      }
      return path.slice(1);
    }
    return path;
  }
  return path;
}

// ================= AI Stylist Logic =================
const AI_PRESETS = {
  'office wear, breathable cotton': {
    summary: 'For the office, you need breathable fabrics, clean cuts and effortless polish for long workdays.',
    picks: [
      { id: 'straight', reason: 'Crisp block-printed pure cotton with tailored structure that keeps you fresh and confident all day.' },
      { id: 'short', reason: 'Pairs neatly with formal cigarette trousers or dark denims for smart-casual finesse.' }
    ]
  },
  'haldi ceremony, something bright': {
    summary: 'Festive sunshine hues and celebratory twirls made for vibrant, joy-filled rituals.',
    picks: [
      { id: 'anarkali', reason: 'Vibrant Marigold with twirl-worthy flair and artisanal finish — an absolute showstopper for Haldi.' },
      { id: 'aline', reason: 'Luminously soft ivory with delicate thread work that catches festive light beautifully.' }
    ]
  },
  'loose and comfy for travel': {
    summary: 'Roomy, airy silhouettes that let you move freely and feel comfortable across journeys.',
    picks: [
      { id: 'kaftan', reason: 'Endlessly breezy and relaxed silhouette in earth tones, made for effortless transit.' },
      { id: 'coord', reason: 'Matched kurti and pants in ultra-soft fabric — instant chic with maximum travel comfort.' }
    ]
  }
};

function queryAIStylist(promptText) {
  const clean = promptText.trim().toLowerCase();
  for (const [key, val] of Object.entries(AI_PRESETS)) {
    if (clean.includes(key) || key.includes(clean)) {
      return val;
    }
  }

  // Dynamic keyword matching
  if (clean.includes('wedding') || clean.includes('haldi') || clean.includes('festiv') || clean.includes('party') || clean.includes('twirl') || clean.includes('bright') || clean.includes('yellow')) {
    return {
      summary: 'Festive celebrations call for grace, vivid heritage colors, and artisanal craftsmanship.',
      picks: [
        { id: 'anarkali', reason: 'Rich festive silhouette with statement flare that moves effortlessly at celebrations.' },
        { id: 'aline', reason: 'Subtle thread work with a soft, flattering flare suitable for day and evening festivities.' }
      ]
    };
  }

  if (clean.includes('office') || clean.includes('work') || clean.includes('formal') || clean.includes('cotton') || clean.includes('daily') || clean.includes('interview')) {
    return {
      summary: 'Workwear favorites balancing comfort, structure, and breathable handcraft.',
      picks: [
        { id: 'straight', reason: 'Clean straight cut in authentic block-printed cotton, designed for everyday professionalism.' },
        { id: 'short', reason: 'Versatile contemporary length that looks sharp with trousers or palazzos.' }
      ]
    };
  }

  if (clean.includes('travel') || clean.includes('flight') || clean.includes('airport') || clean.includes('loose') || clean.includes('comfy') || clean.includes('vacation') || clean.includes('casual')) {
    return {
      summary: 'Easy-breezy silhouettes designed for effortless mobility and laid-back elegance.',
      picks: [
        { id: 'kaftan', reason: 'Unrestricted drape with airy roominess that feels like a gentle breeze.' },
        { id: 'angrakha', reason: 'Flattering wrap cut with side tie details that you can adjust for personalized ease.' }
      ]
    };
  }

  // Default balanced recommendation
  return {
    summary: `Curated recommendation for "${promptText}": timeless hand-crafted kurtis woven for everyday grace.`,
    picks: [
      { id: 'straight', reason: 'Our most versatile straight silhouette, beloved for its effortless charm.' },
      { id: 'coord', reason: 'A coordinated set that effortlessly transitions between casual outings and formal occasions.' }
    ]
  };
}

// Initializer on DOM Ready
document.addEventListener('DOMContentLoaded', () => {
  updateHeaderBagCount();
});

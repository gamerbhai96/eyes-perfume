import { createContext, useContext, useEffect, useState } from 'react';
import { useAuth } from './use-auth';
import { API_URL } from '@/lib/api';

interface CartItem {
  perfumeId: number;
  quantity: number;
}

interface CartContextType {
  cart: CartItem[];
  cartCount: number;
  fetchCart: () => void;
  addToCart: (perfumeId: number, quantity?: number) => Promise<void>;
}

const CartContext = createContext<CartContextType | undefined>(undefined);

export const CartProvider = ({ children }: { children: React.ReactNode }) => {
  const { token } = useAuth();
  const [cart, setCart] = useState<CartItem[]>([]);

  const fetchCart = async () => {
    if (!token) return setCart([]);
    try {
      const res = await fetch(`${API_URL}/cart`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      const data = await res.json();
      setCart(Array.isArray(data) ? data : []);
    } catch {
      setCart([]);
    }
  };

  useEffect(() => {
    fetchCart();
    // eslint-disable-next-line
  }, [token]);

  const addToCart = async (perfumeId: number, quantity: number = 1) => {
    if (!token) throw new Error('Not authenticated');
    const res = await fetch(`${API_URL}/cart`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`
      },
      body: JSON.stringify({ perfumeId, quantity })
    });
    if (!res.ok) {
      throw new Error('Failed to add to cart');
    }
    await fetchCart();
  };

  const contextValue: CartContextType = {
    cart,
    cartCount: cart.length,
    fetchCart,
    addToCart,
  };

  return (
    <CartContext.Provider value={contextValue}>
      {children}
    </CartContext.Provider>
  );
};

export const useCart = () => {
  const context = useContext(CartContext);
  if (context === undefined) {
    throw new Error('useCart must be used within a CartProvider');
  }
  return context;
};
import { createContext, useContext, useEffect, useState } from 'react';
import { useAuth } from './use-auth';

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
      const res = await fetch('http://localhost:4000/api/cart', {
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
    const res = await fetch('http://localhost:4000/api/cart', {
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

  return (
    <CartContext.Provider value={{ cart, cartCount: cart.reduce((sum, i) => sum + i.quantity, 0), fetchCart, addToCart }}>
      {children}
    </CartContext.Provider>
  );
};

export const useCart = () => {
  const ctx = useContext(CartContext);
  if (!ctx) throw new Error('useCart must be used within CartProvider');
  return ctx;
}; 
 
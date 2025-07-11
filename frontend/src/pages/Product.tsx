import React, { useState } from "react";
import { useParams, useNavigate } from 'react-router-dom';
import { perfumes } from '../data/perfumes'; // fallback for mock data
import { useQuery } from '@tanstack/react-query';
import { useCart } from '@/hooks/use-cart';
import { useAuth } from '@/hooks/use-auth';
import { Card, CardContent } from '@/components/ui/card';
import { Star, Heart } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { API_URL } from '@/lib/api';

const fetchProduct = async (id: string | undefined) => {
  if (!id) throw new Error('No product ID');
  const res = await fetch(`${API_URL}/products/${id}`);
  if (!res.ok) throw new Error('Product not found');
  return res.json();
};

const DEFAULT_PERFUME_IMAGE = "https://images.pexels.com/photos/1895015/pexels-photo-1895015.jpeg";

const Product: React.FC = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const { addToCart } = useCart();
  const { token } = useAuth();
  const { data: product, isLoading, error } = useQuery({
    queryKey: ['product', id],
    queryFn: () => fetchProduct(id),
    retry: false,
  });
  const [mainImg, setMainImg] = useState(
    (product?.images?.[0] && product.images[0].trim()) ||
    (product?.image && product.image.trim()) ||
    DEFAULT_PERFUME_IMAGE
  );
  const [buying, setBuying] = useState(false);
  const [cartMsg, setCartMsg] = useState('');

  React.useEffect(() => {
    if (product?.images?.[0]) setMainImg(product.images[0]);
    else if (product?.image) setMainImg(product.image);
  }, [product]);

  // Related products logic
  const getRelated = (current: any) => {
    if (!current) return [];
    let related = (perfumes.filter(p => p.category === current.category && p.id !== current.id));
    if (related.length < 4) {
      // Fill with random others if not enough
      const others = perfumes.filter(p => p.id !== current.id && !related.includes(p));
      while (related.length < 4 && others.length) {
        const idx = Math.floor(Math.random() * others.length);
        related.push(others.splice(idx, 1)[0]);
      }
    }
    return related.slice(0, 4);
  };

  const handleBuyNow = async () => {
    if (!token) {
      navigate('/login');
      return;
    }
    setBuying(true);
    try {
      await addToCart(Number(product?.id ?? id), 1);
      navigate('/cart');
    } catch (err) {
      setCartMsg('Failed to add to cart');
      setTimeout(() => setCartMsg(''), 2000);
    } finally {
      setBuying(false);
    }
  };

  const handleAddToCart = async (perfumeId: number) => {
    if (!token) {
      navigate('/login');
      return;
    }
    setBuying(true);
    try {
      await addToCart(perfumeId, 1);
      setCartMsg('Added to cart!');
    } catch {
      setCartMsg('Failed to add to cart');
    } finally {
      setBuying(false);
      setTimeout(() => setCartMsg(''), 2000);
    }
  };

  if (isLoading) return <div className="min-h-[60vh] flex items-center justify-center text-lg">Loading...</div>;
  if (!product || error) {
    // fallback to mock data if backend fails
    const fallback = perfumes.find(p => p.id === Number(id));
    if (!fallback) {
      return (
        <div className="max-w-2xl mx-auto p-8 text-center">
          <h2 className="text-2xl font-bold mb-4">Product not found</h2>
          <p className="text-muted-foreground">Sorry, we couldn't find the perfume you're looking for.</p>
        </div>
      );
    }
    // fallback related
    const related = getRelated(fallback);
    return (
      <div className="max-w-6xl mx-auto p-4 md:p-8 bg-background rounded-xl shadow-lg mt-8 mb-12 pt-32 md:pt-36">
        <div className="flex flex-col md:flex-row gap-10 md:gap-16">
          {/* Image Gallery */}
          <div className="flex flex-col gap-4 md:w-1/2">
            <div className="bg-white rounded-lg border flex items-center justify-center h-96 overflow-hidden">
              <img src={fallback.images?.[0] || fallback.image || '/public/placeholder.svg'} alt={fallback.name} className="object-contain h-full w-full transition-all duration-300" />
            </div>
            <div className="flex gap-2 mt-2">
              {(fallback.images || [fallback.image]).map((img: string, idx: number) => (
                <img
                  key={idx}
                  src={img}
                  alt={`Thumbnail ${idx+1}`}
                  className={`w-20 h-20 object-cover rounded border cursor-pointer transition-all duration-200 ${fallback.images?.[0] === img ? 'ring-2 ring-primary scale-105' : 'opacity-80 hover:opacity-100'}`}
                />
              ))}
            </div>
          </div>
          {/* Product Info */}
          <div className="flex-1 flex flex-col gap-6">
            <div>
              <h2 className="text-3xl md:text-4xl font-bold mb-2 text-foreground">{fallback.name}</h2>
              <div className="flex items-center gap-3 mb-2">
                <span className="text-base text-muted-foreground capitalize">{fallback.category}</span>
                {fallback.isNew && <span className="ml-2 px-2 py-0.5 rounded bg-primary text-xs text-white font-semibold">New</span>}
                {fallback.isBestseller && <span className="ml-2 px-2 py-0.5 rounded bg-yellow-400 text-xs text-black font-semibold">Bestseller</span>}
              </div>
              <div className="flex items-end gap-4 mb-4">
                <span className="text-3xl font-bold text-primary">${fallback.price}</span>
                {fallback.originalPrice && (
                  <span className="line-through text-lg text-muted-foreground">${fallback.originalPrice}</span>
                )}
                {fallback.originalPrice && (
                  <span className="text-green-600 font-medium text-base">{Math.round(100 - (fallback.price / fallback.originalPrice) * 100)}% off</span>
                )}
              </div>
            </div>
            <p className="text-lg text-gray-700 dark:text-gray-300 mb-4">{fallback.description}</p>
            <div className="flex flex-col sm:flex-row gap-4 mb-4">
              <button className="flex-1 glow-effect bg-primary text-black px-6 py-3 rounded-lg text-lg font-semibold shadow hover:bg-primary/90 transition disabled:opacity-60" onClick={() => handleAddToCart(Number(fallback.id))} disabled={buying}>{buying ? 'Processing...' : 'Add to Cart'}</button>
              <button className="flex-1 glow-effect bg-primary text-black px-6 py-3 rounded-lg text-lg font-semibold shadow hover:bg-primary/90 transition disabled:opacity-60" onClick={handleBuyNow} disabled={buying}>{buying ? 'Processing...' : 'Buy Now'}</button>
            </div>
            {cartMsg && <div className="text-red-600 text-sm mb-2">{cartMsg}</div>}
            <div className="border-t pt-6 mt-4">
              <div className="flex items-center gap-2 mb-2">
                <span className="text-yellow-500 text-xl">★</span>
                <span className="font-medium text-lg">{fallback.rating} / 5</span>
              </div>
              {/* Reviews and review form will go here */}
            </div>
          </div>
        </div>
        {/* Related Products */}
        <div className="w-full mt-16">
          <h3 className="text-2xl font-bold mb-4">Related Products</h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-8 max-w-6xl mx-auto">
            {related.map((rp, index) => (
              <Card
                key={rp.id}
                className="perfume-card border-border/50 stagger-animation overflow-hidden cursor-pointer"
                style={{ animationDelay: `${index * 0.2}s` }}
              >
                <div
                  className="block group"
                  onClick={() => navigate(`/products/${rp.id}`)}
                  style={{ textDecoration: 'none' }}
                  tabIndex={-1}
                >
                  <div className="relative overflow-hidden">
                    <img
                      src={(rp.images?.[0] && rp.images[0].trim()) || (rp.image && rp.image.trim()) || DEFAULT_PERFUME_IMAGE}
                      alt={rp.name}
                      className="w-full h-80 object-cover transition-transform duration-700 group-hover:scale-110"
                    />
                    <div className="absolute inset-0 bg-gradient-to-t from-background/80 via-transparent to-transparent" />
                    <div className="absolute top-4 right-4">
                      <Heart className="h-6 w-6 text-white/80 hover:text-primary transition-colors cursor-pointer" />
                    </div>
                  </div>
                  <CardContent className="p-6">
                    <div className="flex justify-between items-start mb-3">
                      <h3 className="text-xl font-playfair font-semibold line-clamp-1">{rp.name}</h3>
                      <span className="text-lg font-bold text-primary">${rp.price}</span>
                    </div>
                    <p className="text-muted-foreground mb-4 line-clamp-2">{rp.description}</p>
                    <div className="flex items-center gap-1 mb-4">
                      {[...Array(5)].map((_, i) => (
                        <Star key={i} className="h-4 w-4 fill-primary text-primary" />
                      ))}
                      <span className="text-sm text-muted-foreground ml-2">(4.8)</span>
                    </div>
                  </CardContent>
                </div>
                <CardContent className="p-6 pt-0">
                  <Button
                    className="w-full"
                    variant="outline"
                    onClick={e => {
                      e.stopPropagation();
                      handleAddToCart(Number(rp.id));
                    }}
                  >
                    Add to Cart
                  </Button>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      </div>
    );
  }

  // related for real product
  const related = getRelated(product);

  return (
    <div className="max-w-6xl mx-auto p-4 md:p-8 bg-background rounded-xl shadow-lg mt-8 mb-12 pt-32 md:pt-36">
      <div className="flex flex-col md:flex-row gap-10 md:gap-16">
        {/* Image Gallery */}
        <div className="flex flex-col gap-4 md:w-1/2">
          <div className="bg-white rounded-lg border flex items-center justify-center h-96 overflow-hidden">
            <img src={mainImg || DEFAULT_PERFUME_IMAGE} alt={product.name} className="object-contain h-full w-full transition-all duration-300" />
          </div>
          <div className="flex gap-2 mt-2">
            {(product.images || [product.image]).map((img: string, idx: number) => {
              const safeImg = (img && img.trim()) || DEFAULT_PERFUME_IMAGE;
              return (
                <img
                  key={idx}
                  src={safeImg}
                  alt={`Thumbnail ${idx+1}`}
                  className={`w-20 h-20 object-cover rounded border cursor-pointer transition-all duration-200 ${mainImg === safeImg ? 'ring-2 ring-primary scale-105' : 'opacity-80 hover:opacity-100'}`}
                  onClick={() => setMainImg(safeImg)}
                />
              );
            })}
          </div>
        </div>
        {/* Product Info */}
        <div className="flex-1 flex flex-col gap-6">
          <div>
            <h2 className="text-3xl md:text-4xl font-bold mb-2 text-foreground">{product.name}</h2>
            <div className="flex items-center gap-3 mb-2">
              <span className="text-base text-muted-foreground capitalize">{product.category}</span>
              {product.isNew && <span className="ml-2 px-2 py-0.5 rounded bg-primary text-xs text-white font-semibold">New</span>}
              {product.isBestseller && <span className="ml-2 px-2 py-0.5 rounded bg-yellow-400 text-xs text-black font-semibold">Bestseller</span>}
            </div>
            <div className="flex items-end gap-4 mb-4">
              <span className="text-3xl font-bold text-primary">${product.price}</span>
              {product.originalPrice && (
                <span className="line-through text-lg text-muted-foreground">${product.originalPrice}</span>
              )}
              {product.originalPrice && (
                <span className="text-green-600 font-medium text-base">{Math.round(100 - (product.price / product.originalPrice) * 100)}% off</span>
              )}
            </div>
          </div>
          <p className="text-lg text-gray-700 dark:text-gray-300 mb-4">{product.description}</p>
          <div className="flex flex-col sm:flex-row gap-4 mb-4">
            <button className="flex-1 glow-effect bg-primary text-black px-6 py-3 rounded-lg text-lg font-semibold shadow hover:bg-primary/90 transition disabled:opacity-60" onClick={() => handleAddToCart(Number(product.id))} disabled={buying}>{buying ? 'Processing...' : 'Add to Cart'}</button>
            <button className="flex-1 glow-effect bg-primary text-black px-6 py-3 rounded-lg text-lg font-semibold shadow hover:bg-primary/90 transition disabled:opacity-60" onClick={handleBuyNow} disabled={buying}>{buying ? 'Processing...' : 'Buy Now'}</button>
          </div>
          {cartMsg && <div className="text-red-600 text-sm mb-2">{cartMsg}</div>}
          <div className="border-t pt-6 mt-4">
            <div className="flex items-center gap-2 mb-2">
              <span className="text-yellow-500 text-xl">★</span>
              <span className="font-medium text-lg">{product.rating} / 5</span>
            </div>
            {/* Reviews and review form will go here */}
          </div>
        </div>
      </div>
      {/* Related Products */}
      <div className="w-full mt-16">
        <h3 className="text-2xl font-bold mb-4">Related Products</h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-8 max-w-6xl mx-auto">
          {related.map((rp, index) => (
            <Card
              key={rp.id}
              className="perfume-card border-border/50 stagger-animation overflow-hidden cursor-pointer"
              style={{ animationDelay: `${index * 0.2}s` }}
            >
              <div
                className="block group"
                onClick={() => navigate(`/products/${rp.id}`)}
                style={{ textDecoration: 'none' }}
                tabIndex={-1}
              >
                <div className="relative overflow-hidden">
                  <img
                    src={(rp.images?.[0] && rp.images[0].trim()) || (rp.image && rp.image.trim()) || DEFAULT_PERFUME_IMAGE}
                    alt={rp.name}
                    className="w-full h-80 object-cover transition-transform duration-700 group-hover:scale-110"
                  />
                  <div className="absolute inset-0 bg-gradient-to-t from-background/80 via-transparent to-transparent" />
                  <div className="absolute top-4 right-4">
                    <Heart className="h-6 w-6 text-white/80 hover:text-primary transition-colors cursor-pointer" />
                  </div>
                </div>
                <CardContent className="p-6">
                  <div className="flex justify-between items-start mb-3">
                    <h3 className="text-xl font-playfair font-semibold line-clamp-1">{rp.name}</h3>
                    <span className="text-lg font-bold text-primary">${rp.price}</span>
                  </div>
                  <p className="text-muted-foreground mb-4 line-clamp-2">{rp.description}</p>
                  <div className="flex items-center gap-1 mb-4">
                    {[...Array(5)].map((_, i) => (
                      <Star key={i} className="h-4 w-4 fill-primary text-primary" />
                    ))}
                    <span className="text-sm text-muted-foreground ml-2">(4.8)</span>
                  </div>
                </CardContent>
              </div>
              <CardContent className="p-6 pt-0">
                <Button
                  className="w-full"
                  variant="outline"
                  onClick={e => {
                    e.stopPropagation();
                    handleAddToCart(Number(rp.id));
                  }}
                >
                  Add to Cart
                </Button>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    </div>
  );
};

export default Product; 
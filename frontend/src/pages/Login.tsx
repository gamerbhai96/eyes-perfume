import { useState, useEffect } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Separator } from '@/components/ui/separator';
import { Sparkles, Eye, EyeOff, Mail, Lock, KeyRound } from 'lucide-react';
import { useAuth } from '@/hooks/use-auth';
import { API_URL } from '@/lib/api';

const Login = () => {
  const [showPassword, setShowPassword] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [otpStep, setOtpStep] = useState(false);
  const [otp, setOtp] = useState('');
  const [tempToken, setTempToken] = useState('');
  const { login: authLogin } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();

  // Get redirect path from location.state
  const redirectPath = location.state?.from?.pathname || '/';

  // Handle Google OAuth redirect
  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const token = params.get('token');
    const user = params.get('user');
    if (token && user) {
      try {
        const userObj = JSON.parse(decodeURIComponent(user));
        authLogin(token, userObj);
        navigate('/');
      } catch (e) {
        // ignore
      }
    }
  }, [location, authLogin, navigate]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
      const res = await fetch(`${API_URL}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || 'Login failed');
      } else if (data.otpRequired) {
        setOtpStep(true);
        setTempToken(data.tempToken);
      } else if (data.token && data.user) {
        authLogin(data.token, data.user);
        window.location.replace(redirectPath);
      } else {
        setError('Unexpected response.');
      }
    } catch (err) {
      setError('Network error');
    } finally {
      setLoading(false);
    }
  };

  const handleOtpSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
      const res = await fetch(`${API_URL}/verify-otp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, otp, tempToken })
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || 'OTP verification failed');
      } else if (data.token && data.user) {
        authLogin(data.token, data.user);
        window.location.replace(redirectPath);
      } else {
        setError('Unexpected response.');
      }
    } catch (err) {
      setError('Network error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-hero p-6">
      <div className="absolute inset-0 bg-[url('https://images.unsplash.com/photo-1506905925346-21bda4d32df4?w=1920&h=1080&fit=crop')] bg-cover bg-center opacity-5" />
      
      <div className="w-full max-w-md relative z-10">
        {/* Logo */}
        <div className="text-center mb-8 fade-in">
          <Link to="/" className="inline-flex items-center gap-3 group">
            <div className="relative">
              <Sparkles className="h-10 w-10 text-primary group-hover:rotate-12 transition-transform duration-300" />
              <div className="absolute inset-0 h-10 w-10 text-primary opacity-30 group-hover:animate-ping" />
            </div>
            <span className="text-3xl font-playfair font-bold gradient-text">
              EYES
            </span>
          </Link>
        </div>

        <Card className="perfume-card border-border/50 fade-in" style={{animationDelay: '0.2s'}}>
          <CardHeader className="text-center pb-6">
            <CardTitle className="text-2xl font-playfair font-bold">
              {otpStep ? 'Enter OTP' : 'Welcome Back'}
            </CardTitle>
            <CardDescription className="text-muted-foreground">
              {otpStep ? 'Check your email for a 6-digit code' : 'Sign in to your account to continue your fragrance journey'}
            </CardDescription>
          </CardHeader>
          
          <CardContent className="space-y-6">
            {!otpStep ? (
            <form onSubmit={handleSubmit} className="space-y-4">
              {/* Email */}
              <div className="space-y-2">
                <Label htmlFor="email" className="text-sm font-medium">
                  Email Address
                </Label>
                <div className="relative">
                  <Mail className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-muted-foreground" />
                  <Input
                    id="email"
                    type="email"
                    placeholder="your@email.com"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="pl-10"
                    required
                  />
                </div>
              </div>

              {/* Password */}
              <div className="space-y-2">
                <Label htmlFor="password" className="text-sm font-medium">
                  Password
                </Label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-muted-foreground" />
                  <Input
                    id="password"
                    type={showPassword ? "text" : "password"}
                    placeholder="Enter your password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="pl-10 pr-10"
                    required
                  />
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    className="absolute right-1 top-1/2 transform -translate-y-1/2 h-8 w-8"
                    onClick={() => setShowPassword(!showPassword)}
                  >
                    {showPassword ? (
                      <EyeOff className="h-4 w-4" />
                    ) : (
                      <Eye className="h-4 w-4" />
                    )}
                  </Button>
                </div>
              </div>

              {/* Remember Me & Forgot Password */}
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <input
                    type="checkbox"
                    id="remember"
                    className="rounded border-border text-primary focus:ring-primary"
                  />
                  <Label htmlFor="remember" className="text-sm text-muted-foreground">
                    Remember me
                  </Label>
                </div>
                <Link 
                  to="/forgot-password" 
                  className="text-sm text-primary hover:text-primary-glow transition-colors"
                >
                  Forgot password?
                </Link>
              </div>

                {/* Error Message */}
                {error && (
                  <div className="text-red-500 text-sm text-center">{error}</div>
                )}

              {/* Submit Button */}
                <Button type="submit" className="w-full glow-effect" disabled={loading}>
                  {loading ? 'Signing In...' : 'Sign In'}
                </Button>
              </form>
            ) : (
              <form onSubmit={handleOtpSubmit} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="otp" className="text-sm font-medium">
                    OTP Code
                  </Label>
                  <div className="relative">
                    <KeyRound className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-muted-foreground" />
                    <Input
                      id="otp"
                      type="text"
                      inputMode="numeric"
                      pattern="[0-9]{6}"
                      placeholder="6-digit code"
                      value={otp}
                      onChange={(e) => setOtp(e.target.value)}
                      className="pl-10 tracking-widest text-lg text-center"
                      maxLength={6}
                      required
                    />
                  </div>
                </div>
                {error && (
                  <div className="text-red-500 text-sm text-center">{error}</div>
                )}
                <Button type="submit" className="w-full glow-effect" disabled={loading}>
                  {loading ? 'Verifying...' : 'Verify & Sign In'}
              </Button>
            </form>
            )}

            {/* Divider */}
            {!otpStep && (
            <div className="relative">
              <Separator />
              <span className="absolute left-1/2 top-1/2 transform -translate-x-1/2 -translate-y-1/2 bg-card px-3 text-sm text-muted-foreground">
                or
              </span>
            </div>
            )}

            {/* Sign Up Link */}
            <div className="text-center">
              <span className="text-sm text-muted-foreground">
                Don't have an account?{" "}
                <Link 
                  to="/signup" 
                  className="text-primary hover:text-primary-glow transition-colors font-medium"
                >
                  Sign up
                </Link>
              </span>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default Login;
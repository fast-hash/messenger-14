import { useEffect, useState } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import PropTypes from 'prop-types';
import LoginForm from '../components/LoginForm';

const LoginPage = ({ onLogin }) => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    if (location.state?.accessDisabled) {
      setError('Доступ ограничен администратором');
      navigate('/login', { replace: true, state: {} });
    }
  }, [location.state, navigate]);

  const handleSubmit = async (credentials) => {
    try {
      setLoading(true);
      setError(null);
      await onLogin(credentials);
      navigate('/chats');
    } catch (err) {
      const code = err.response?.data?.code;
      if (code === 'ACCESS_DISABLED') {
        setError('Доступ ограничен администратором');
      } else {
        setError(err.response?.data?.error || 'Не удалось войти');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-layout">
      <div className="auth-panel">
        <h1>Добро пожаловать в MediChat</h1>
        <p className="auth-subtitle">Войдите под корпоративным аккаунтом, чтобы продолжить общение.</p>
        <LoginForm onSubmit={handleSubmit} loading={loading} error={error} />
        <p className="auth-switch">
          Нет аккаунта? <Link to="/register">Зарегистрируйтесь</Link>
        </p>
      </div>
    </div>
  );
};

LoginPage.propTypes = {
  onLogin: PropTypes.func.isRequired,
};

export default LoginPage;

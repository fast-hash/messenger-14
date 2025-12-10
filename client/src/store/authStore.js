import { create } from 'zustand';
import * as authApi from '../api/authApi';
import * as usersApi from '../api/usersApi';

export const useAuthStore = create((set) => ({
  user: null,
  loading: true,
  dndEnabled: false,
  dndUntil: null,
  device: null,
  async fetchCurrentUser() {
    try {
      const { user, device } = await usersApi.currentUser();
      set({
        user,
        loading: false,
        dndEnabled: user.dndEnabled || false,
        dndUntil: user.dndUntil || null,
        device: device || null,
      });
    } catch (error) {
      set({ user: null, loading: false, dndEnabled: false, dndUntil: null, device: null });
    }
  },
  async login(credentials) {
    const { user, device } = await authApi.login(credentials);
    set({
      user,
      dndEnabled: user.dndEnabled || false,
      dndUntil: user.dndUntil || null,
      device: device || null,
    });
  },
  async register(payload) {
    const data = await authApi.register(payload);
    return data;
  },
  async logout() {
    try {
      await authApi.logout();
    } catch (e) {
      // ignore logout errors (e.g., expired session)
    }
    set({ user: null, dndEnabled: false, dndUntil: null, device: null });
  },
  async updatePreferences(preferences) {
    const { user } = await usersApi.updatePreferences(preferences);
    set({ user, dndEnabled: user.dndEnabled || false, dndUntil: user.dndUntil || null });
  },
}));

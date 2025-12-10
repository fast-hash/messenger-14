import httpClient from './httpClient';
import { getOrCreateDeviceId } from '../utils/deviceId';
import UAParser from 'ua-parser-js';

const buildDevicePayload = () => {
  const parser = new UAParser();
  const result = parser.getResult();
  const browserName = result.browser?.name ? result.browser.name : 'Unknown Browser';
  const browserVersion = result.browser?.version ? ` ${result.browser.version}` : '';
  const osName = result.os?.name ? result.os.name : 'Unknown OS';
  const osVersion = result.os?.version ? ` ${result.os.version}` : '';

  return {
    deviceId: getOrCreateDeviceId(),
    name: `${browserName}${browserVersion}`.trim(),
    platform: `${osName}${osVersion}`.trim(),
  };
};

export const register = async (payload) => {
  const { data } = await httpClient.post('/api/auth/register', payload);
  return data;
};

export const login = async (payload) => {
  const { data } = await httpClient.post('/api/auth/login', {
    ...payload,
    device: buildDevicePayload(),
  });
  return data;
};

export const logout = async () => {
  await httpClient.post('/api/auth/logout');
};

export const me = async () => {
  const { data } = await httpClient.get('/api/auth/me');
  return data;
};

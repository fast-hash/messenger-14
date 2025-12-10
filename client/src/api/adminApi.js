import httpClient from './httpClient';

export const listUsers = async () => {
  const { data } = await httpClient.get('/api/admin/users');
  return data;
};

export const disableUser = async (userId) => {
  const { data } = await httpClient.post(`/api/admin/users/${userId}/disable`);
  return data;
};

export const enableUser = async (userId) => {
  const { data } = await httpClient.post(`/api/admin/users/${userId}/enable`);
  return data;
};

export const listRegistrationRequests = async () => {
  const { data } = await httpClient.get('/api/admin/registration-requests');
  return data;
};

export const approveRegistrationRequest = async (requestId) => {
  const { data } = await httpClient.post(`/api/admin/registration-requests/${requestId}/approve`);
  return data;
};

export const rejectRegistrationRequest = async (requestId) => {
  await httpClient.post(`/api/admin/registration-requests/${requestId}/reject`);
};

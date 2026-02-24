export type Paging = { page?: number; pageSize?: number } | undefined;

// Cross-module types used by warden views

export interface AdminUser {
  id?: number;
  username?: string;
  nickname?: string;
  realname?: string;
  avatar?: string;
  email?: string;
}

export interface AdminRole {
  id?: number;
  name?: string;
  code?: string;
  description?: string;
}

// Sharing module types used by folder/index.vue

export type SharePolicyType =
  | 'SHARE_POLICY_TYPE_BLACKLIST'
  | 'SHARE_POLICY_TYPE_WHITELIST';

export type SharePolicyMethod =
  | 'SHARE_POLICY_METHOD_IP'
  | 'SHARE_POLICY_METHOD_MAC'
  | 'SHARE_POLICY_METHOD_REGION'
  | 'SHARE_POLICY_METHOD_TIME'
  | 'SHARE_POLICY_METHOD_DEVICE'
  | 'SHARE_POLICY_METHOD_NETWORK';

export interface CreateSharePolicyInput {
  type: SharePolicyType;
  method: SharePolicyMethod;
  value: string;
  reason?: string;
}

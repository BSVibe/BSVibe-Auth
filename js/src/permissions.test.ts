import { describe, it, expect } from 'vitest';
import { hasPermission } from './permissions';
import type { Tenant, User } from './types';

const user: User = {
  id: 'u1',
  email: 'alice@example.com',
};

function makeTenant(role: Tenant['role'], plan: Tenant['plan']): Tenant {
  return {
    id: 't1',
    name: 'Test Tenant',
    type: 'org',
    role,
    plan,
  };
}

describe('hasPermission', () => {
  describe('null/undefined inputs', () => {
    it('returns false when user is null', () => {
      expect(hasPermission(null, makeTenant('owner', 'pro'), 'bsage.note.read')).toBe(false);
    });

    it('returns false when activeTenant is null', () => {
      expect(hasPermission(user, null, 'bsage.note.read')).toBe(false);
    });
  });

  describe('viewer role', () => {
    it('allows read on any product when plan is free+', () => {
      const t = makeTenant('viewer', 'free');
      expect(hasPermission(user, t, 'bsage.note.read')).toBe(true);
      expect(hasPermission(user, t, 'nexus.project.read')).toBe(true);
      expect(hasPermission(user, t, 'gateway.rule.read')).toBe(true);
      expect(hasPermission(user, t, 'supervisor.cost.read')).toBe(true);
    });

    it('denies write/create/delete/manage', () => {
      const t = makeTenant('viewer', 'pro');
      expect(hasPermission(user, t, 'bsage.note.write')).toBe(false);
      expect(hasPermission(user, t, 'nexus.project.create')).toBe(false);
      expect(hasPermission(user, t, 'nexus.project.delete')).toBe(false);
      expect(hasPermission(user, t, 'core.tenant.manage')).toBe(false);
    });

    it('denies execute (gated by plan even for higher roles)', () => {
      const t = makeTenant('viewer', 'pro');
      expect(hasPermission(user, t, 'nexus.task.execute')).toBe(false);
    });
  });

  describe('member role', () => {
    it('allows read + write + create on free plan', () => {
      const t = makeTenant('member', 'free');
      expect(hasPermission(user, t, 'bsage.note.read')).toBe(true);
      expect(hasPermission(user, t, 'bsage.note.write')).toBe(true);
      expect(hasPermission(user, t, 'bsage.note.create')).toBe(true);
    });

    it('denies delete on free plan', () => {
      const t = makeTenant('member', 'free');
      expect(hasPermission(user, t, 'bsage.note.delete')).toBe(false);
    });

    it('allows delete on pro+', () => {
      expect(hasPermission(user, makeTenant('member', 'pro'), 'bsage.note.delete')).toBe(true);
      expect(hasPermission(user, makeTenant('member', 'team'), 'bsage.note.delete')).toBe(true);
    });

    it('denies manage permissions', () => {
      const t = makeTenant('member', 'enterprise');
      expect(hasPermission(user, t, 'core.tenant.manage')).toBe(false);
      expect(hasPermission(user, t, 'core.member.invite')).toBe(false);
    });

    it('execute requires pro+', () => {
      expect(hasPermission(user, makeTenant('member', 'free'), 'nexus.task.execute')).toBe(false);
      expect(hasPermission(user, makeTenant('member', 'pro'), 'nexus.task.execute')).toBe(true);
      expect(hasPermission(user, makeTenant('member', 'team'), 'nexus.task.execute')).toBe(true);
    });
  });

  describe('admin role', () => {
    it('allows all CRUD on free plan', () => {
      const t = makeTenant('admin', 'free');
      expect(hasPermission(user, t, 'bsage.note.read')).toBe(true);
      expect(hasPermission(user, t, 'bsage.note.write')).toBe(true);
      expect(hasPermission(user, t, 'bsage.note.create')).toBe(true);
      expect(hasPermission(user, t, 'bsage.note.delete')).toBe(true);
    });

    it('allows member.invite on team+', () => {
      expect(hasPermission(user, makeTenant('admin', 'free'), 'core.member.invite')).toBe(false);
      expect(hasPermission(user, makeTenant('admin', 'pro'), 'core.member.invite')).toBe(false);
      expect(hasPermission(user, makeTenant('admin', 'team'), 'core.member.invite')).toBe(true);
      expect(hasPermission(user, makeTenant('admin', 'enterprise'), 'core.member.invite')).toBe(true);
    });

    it('denies tenant.manage (owner-only)', () => {
      expect(hasPermission(user, makeTenant('admin', 'enterprise'), 'core.tenant.manage')).toBe(false);
    });

    it('execute requires pro+', () => {
      expect(hasPermission(user, makeTenant('admin', 'free'), 'nexus.task.execute')).toBe(false);
      expect(hasPermission(user, makeTenant('admin', 'pro'), 'nexus.task.execute')).toBe(true);
    });
  });

  describe('owner role', () => {
    it('allows tenant.manage', () => {
      expect(hasPermission(user, makeTenant('owner', 'free'), 'core.tenant.manage')).toBe(true);
    });

    it('allows member.invite on team+', () => {
      expect(hasPermission(user, makeTenant('owner', 'free'), 'core.member.invite')).toBe(false);
      expect(hasPermission(user, makeTenant('owner', 'team'), 'core.member.invite')).toBe(true);
    });

    it('allows execute on pro+', () => {
      expect(hasPermission(user, makeTenant('owner', 'free'), 'nexus.task.execute')).toBe(false);
      expect(hasPermission(user, makeTenant('owner', 'pro'), 'nexus.task.execute')).toBe(true);
    });

    it('allows all CRUD always', () => {
      const t = makeTenant('owner', 'free');
      expect(hasPermission(user, t, 'bsage.note.delete')).toBe(true);
      expect(hasPermission(user, t, 'gateway.apikey.create')).toBe(true);
    });
  });

  describe('malformed permissions', () => {
    it('returns false for invalid permission format', () => {
      const t = makeTenant('owner', 'enterprise');
      expect(hasPermission(user, t, 'invalid')).toBe(false);
      expect(hasPermission(user, t, '')).toBe(false);
      expect(hasPermission(user, t, 'a.b')).toBe(false);
    });

    it('returns false for unknown action', () => {
      const t = makeTenant('owner', 'enterprise');
      expect(hasPermission(user, t, 'bsage.note.unknown')).toBe(false);
    });
  });
});

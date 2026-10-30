import test from 'node:test';
import {assertPublicMcpRetired} from './retirement-runtime-test-helpers.mjs';
test('actual public bundle in workerd retires all legacy ingress without egress', {timeout: 30000}, assertPublicMcpRetired);

-- Phase 11: demo applications and resources.
--
-- Five services across the four sensitivity levels (spec §9, §16). They exist
-- so the same behaviour produces a different answer depending on what is being
-- reached — the contextual part of the trust model — and so the demonstration
-- has something real to protect.

INSERT INTO applications (key, name, description, sensitivity, launch_url) VALUES
    ('mail',        'Mail',                     'Departmental email.',                          'INTERNAL',  'http://localhost:8110/mail'),
    ('collab',      'Collaboration',            'Team workspace and document sharing.',         'INTERNAL',  'http://localhost:8110/collab'),
    ('portal',      'Internal Portal',          'Staff directory, policies and announcements.', 'INTERNAL',  'http://localhost:8110/portal'),
    ('operations',  'Operations Portal',        'Operational records and field reporting.',     'SENSITIVE', 'http://localhost:8110/operations'),
    ('critical',    'Critical Resource Portal', 'Classified operational material.',             'CRITICAL',  'http://localhost:8110/critical')
ON CONFLICT (key) DO NOTHING;

-- Resources within each application. Sensitivity is per resource, not only per
-- application: a directory listing inside an operational system is not as
-- sensitive as the records it indexes.
INSERT INTO resources (application_id, key, name, description, sensitivity)
SELECT a.id, r.key, r.name, r.description, r.sensitivity::sensitivity
FROM applications a
JOIN (VALUES
    ('mail',       'inbox',            'Inbox',                     'Message metadata only.',                 'INTERNAL'),
    ('collab',     'workspace',        'Team workspace',            'Shared documents.',                      'INTERNAL'),
    ('portal',     'directory',        'Staff directory',           'Names, roles and departments.',          'PUBLIC'),
    ('portal',     'policies',         'Policy library',            'Published internal policy.',             'INTERNAL'),
    ('operations', 'field-reports',    'Field reports',             'Operational reporting records.',         'SENSITIVE'),
    ('operations', 'personnel',        'Personnel records',         'Staff records held by operations.',      'SENSITIVE'),
    ('critical',   'operations-db',    'Operations database',       'Live operational database.',             'CRITICAL'),
    ('critical',   'deployment-plans', 'Deployment plans',          'Classified deployment material.',        'CRITICAL')
) AS r(app_key, key, name, description, sensitivity) ON r.app_key = a.key
ON CONFLICT (application_id, key) DO NOTHING;

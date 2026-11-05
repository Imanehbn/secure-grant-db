-- =====================================================================
-- GrantDB - Phase 4: SYNTHETIC sample data for the vulnerability lab
-- Everything below is invented. No real people, IDs or bank accounts.
-- Run ONCE as root (see docs/phase4_vulnerability_analysis.md).
-- =====================================================================

USE grantdb;

INSERT INTO departments (name, faculty) VALUES
  ('Computer Science',    'Engineering'),
  ('Biomedical Sciences', 'Medicine');

INSERT INTO funding_agencies (name, country, contact_email) VALUES
  ('National Science Fund',    'Morocco', 'grants@nsf.example.test'),
  ('Horizon Research Council', 'EU',      'calls@hrc.example.test');

-- Two extra PI logins, for realistic data only (not meant to be signed into).
INSERT IGNORE INTO users (username, password_hash, role_id, email) VALUES
  ('app_pi2', '$2y$10$usJz0E3kQxM2x1h8n4wQbeYV5qvQnD8y8g9aQxQe8mJZkqWqG9m0y', 3, 'pi2@example.test'),
  ('app_pi3', '$2y$10$usJz0E3kQxM2x1h8n4wQbeYV5qvQnD8y8g9aQxQe8mJZkqWqG9m0y', 3, 'pi3@example.test');

INSERT INTO researchers
  (user_id, department_id, full_name, academic_rank, orcid,
   national_id_enc, phone_enc, bank_account_enc)
SELECT u.user_id, d.department_id, r.full_name, r.academic_rank, r.orcid,
       r.nid, r.phone, r.bank
FROM (
  SELECT 'app_pi'  AS username, 'Computer Science'    AS dept, 'Dr. Salma Alaoui'  AS full_name,
         'Associate Professor' AS academic_rank, '0000-0001-0000-0001' AS orcid,
         'FAKE-ID-AB123456' AS nid, '+212-000-000001' AS phone, 'FAKE-BANK-0001-1111' AS bank
  UNION ALL
  SELECT 'app_pi2', 'Biomedical Sciences', 'Dr. Youssef Benali', 'Professor',
         '0000-0001-0000-0002', 'FAKE-ID-CD789012', '+212-000-000002', 'FAKE-BANK-0002-2222'
  UNION ALL
  SELECT 'app_pi3', 'Computer Science', 'Dr. Nadia Cherkaoui', 'Senior Lecturer',
         '0000-0001-0000-0003', 'FAKE-ID-EF345678', '+212-000-000003', 'FAKE-BANK-0003-3333'
) AS r
JOIN users u       ON u.username = r.username
JOIN departments d ON d.name     = r.dept;

INSERT INTO proposals
  (title, abstract, pi_id, agency_id, requested_amount, status, submitted_at)
SELECT p.title, p.abstract, r.researcher_id, a.agency_id, p.amount, p.status, p.submitted_at
FROM (
  SELECT 'Machine Learning for Crop Disease Detection' AS title,
         'Image models to detect plant disease early.' AS abstract,
         'Dr. Salma Alaoui' AS pi, 'National Science Fund' AS agency,
         120000.00 AS amount, 'Approved' AS status, '2026-03-01 10:00:00' AS submitted_at
  UNION ALL
  SELECT 'Secure IoT Firmware Update Protocol',
         'A signed, rollback-safe update scheme for sensors.',
         'Dr. Nadia Cherkaoui', 'Horizon Research Council', 85000.00, 'Approved', '2026-03-05 09:30:00'
  UNION ALL
  SELECT 'Low-Cost Water Quality Sensors',
         'Open hardware sensors for rural water monitoring.',
         'Dr. Youssef Benali', 'National Science Fund', 60000.00, 'Approved', '2026-03-10 14:00:00'
  UNION ALL
  SELECT 'Federated Learning for Hospital Records',
         'Training models without moving patient data.',
         'Dr. Youssef Benali', 'Horizon Research Council', 150000.00, 'Submitted', '2026-09-20 11:00:00'
  UNION ALL
  SELECT 'Blockchain Voting Prototype',
         'Proof of concept for campus elections.',
         'Dr. Nadia Cherkaoui', 'National Science Fund', 40000.00, 'Rejected', '2026-02-15 16:00:00'
  UNION ALL
  SELECT 'CONFIDENTIAL DRAFT: Novel Battery Anode Idea',
         'Unpublished invention, patent not yet filed.',
         'Dr. Salma Alaoui', 'Horizon Research Council', 300000.00, 'Draft', NULL
  UNION ALL
  SELECT 'CONFIDENTIAL DRAFT: Unpublished Drug Delivery Method',
         'Early results, not shared with any other group.',
         'Dr. Youssef Benali', 'National Science Fund', 220000.00, 'Draft', NULL
) AS p
JOIN researchers r      ON r.full_name = p.pi
JOIN funding_agencies a ON a.name      = p.agency;

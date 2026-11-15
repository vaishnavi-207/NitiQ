export interface HealthResponse {
  product: string;
  status: string;
  version: string;
  phase: string;
  uptime_seconds: number;
  python_version: string;
  platform: string;
}

export interface SimulationAssumptions {
  user_compromise_rate_per_hour: number;
  lateral_movement_delay_minutes: number;
  local_admin_reuse_prob: number;
  domain_admin_escalation_prob: number;
  file_share_encryption_gb_per_hour: number;
  eop_vulnerability_present: boolean;
  backup_wipe_capability: boolean;
  edr_detection_delay_minutes: number;
  backup_restore_mb_s: number;
  reimaging_hours_per_host: number;
}

export interface OrganizationSummary {
  id: string;
  name: string;
  description: string;
  industry: string;
  users_count: number;
  hosts_count: number;
  domain_controllers_count: number;
  file_shares_count: number;
  backup_repositories_count: number;
  network_segments_count: number;
  edges_count: number;
  required_rto_hours: number;
  required_rpo_hours: number;
}

export interface UserEntity {
  id: string;
  name: string;
  department: string;
  role: string;
  host_ids: string[];
  is_domain_admin: boolean;
  mfa_enabled: boolean;
  phishing_risk_score: number;
}

export interface HostEntity {
  id: string;
  hostname: string;
  ip_address: string;
  segment_id: string;
  os_type: string;
  edr_installed: boolean;
  local_admin_count: number;
  has_eop_vulnerability: boolean;
}

export interface DomainControllerEntity {
  id: string;
  hostname: string;
  ip_address: string;
  segment_id: string;
}

export interface FileShareEntity {
  id: string;
  name: string;
  host_id: string;
  total_size_gb: number;
  is_sensitive: boolean;
  backup_protected: boolean;
}

export interface BackupRepoEntity {
  id: string;
  name: string;
  host_id: string;
  repository_type: string;
  is_immutable: boolean;
  is_offline: boolean;
  air_gapped: boolean;
}

export interface NetworkSegmentEntity {
  id: string;
  name: string;
  subnet: string;
  isolated: boolean;
  strict_firewall: boolean;
}

export interface RelationshipEdge {
  source_id: string;
  target_id: string;
  edge_type: string;
  allowed_ports: number[];
}

export interface DefensiveControls {
  mfa_coverage_pct: number;
  edr_coverage_pct: number;
  backup_immutability_pct: number;
  segmentation_strictness_pct: number;
  patch_cadence_days: number;
  security_awareness_score: number;
}

export interface OrganizationProfile {
  id: string;
  name: string;
  description: string;
  industry: string;
  users: UserEntity[];
  hosts: HostEntity[];
  domain_controllers: DomainControllerEntity[];
  file_shares: FileShareEntity[];
  backup_repositories: BackupRepoEntity[];
  network_segments: NetworkSegmentEntity[];
  edges: RelationshipEdge[];
  defensive_controls: DefensiveControls;
  required_rto_hours: number;
  required_rpo_hours: number;
}

export interface ValidationResponse {
  valid: boolean;
  message: string;
  entity_counts: Record<string, number>;
  profile_id: string;
}

export interface HeadlineMetrics {
  blast_radius_composite_pct: number;
  time_to_detect_hours: number;
  recovery_time_hours: number;
  required_rto_hours: number;
  rto_gap_hours: number;
  rto_status: string;
  overall_maturity_score: number;
  maturity_tier: string;
}

export interface TimelineStep {
  step_index: number;
  elapsed_minutes: number;
  newly_compromised: string[];
  total_compromised_count: number;
  compromised_hosts_count: number;
  compromised_shares_count: number;
  compromised_backups_count: number;
  encrypted_data_gb: number;
  detection_triggered: boolean;
  event_description: string;
}

export interface BlastRadiusMetrics {
  total_hosts: number;
  compromised_hosts: number;
  host_compromise_pct: number;
  total_file_shares: number;
  compromised_file_shares: number;
  file_share_compromise_pct: number;
  total_data_gb: number;
  encrypted_data_gb: number;
  data_encrypted_pct: number;
  total_critical_assets: number;
  critical_assets_compromised: number;
  critical_asset_compromise_pct: number;
  domain_controllers_compromised: number;
  domain_admin_reached: boolean;
  total_backup_repositories: number;
  backup_repositories_compromised: number;
  backups_compromised_flag: boolean;
  immutable_backups_survived: boolean;
  composite_blast_radius_pct: number;
}

export interface DetectionMetrics {
  estimated_ttd_hours: number;
  detection_mechanism: string;
  detection_step?: number;
  telemetry_coverage_pct: number;
  is_model_estimate: boolean;
  estimate_note: string;
}

export interface SimulationResult {
  patient_zero_id: string;
  patient_zero_name: string;
  patient_zero_type: string;
  department: string;
  total_steps: number;
  duration_hours: number;
  blast_radius: BlastRadiusMetrics;
  detection: DetectionMetrics;
  timeline: TimelineStep[];
  privilege_escalation_path: string[];
  assumptions_used: SimulationAssumptions;
}

export interface PatientZeroRankingEntry {
  rank: number;
  entity_id: string;
  entity_name: string;
  entity_type: string;
  department: string;
  host_compromise_pct: number;
  data_encrypted_pct: number;
  critical_asset_compromise_pct: number;
  domain_admin_reached: boolean;
  backups_compromised: boolean;
  estimated_ttd_hours: number;
  risk_score: number;
}

export interface PatientZeroRankingResponse {
  worst_case_patient_zero: PatientZeroRankingEntry;
  rankings: PatientZeroRankingEntry[];
  total_evaluated: number;
}

export interface RecoveryStepItem {
  step_name: string;
  duration_hours: number;
  description: string;
}

export interface RecoveryEstimateResponse {
  estimated_recovery_hours: number;
  required_rto_hours: number;
  rto_gap_hours: number;
  rto_status: string;
  is_model_estimate: boolean;
  estimate_disclaimer: string;
  total_data_to_restore_gb: number;
  effective_throughput_mb_s: number;
  top_blockers: string[];
  recovery_breakdown: RecoveryStepItem[];
  backup_status_summary: Record<string, string>;
}

export interface ControlScoreItem {
  control_id: string;
  function: string;
  name: string;
  max_points: number;
  awarded_points: number;
  status: string;
  rationale: string;
}

export interface FunctionScore {
  function: string;
  score: number;
  max_score: number;
  percentage: number;
}

export interface MaturityScoreResponse {
  overall_score: number;
  maturity_level: number;
  maturity_tier: string;
  function_scores: Record<string, FunctionScore>;
  controls_breakdown: ControlScoreItem[];
}

export interface AssessmentResponse {
  organization_id: string;
  organization_name: string;
  industry: string;
  headline_metrics: HeadlineMetrics;
  worst_case_patient_zero: PatientZeroRankingEntry;
  simulation: SimulationResult;
  recovery: RecoveryEstimateResponse;
  scoring: MaturityScoreResponse;
}

export interface RemediationControls {
  enforce_mfa_admin: boolean;
  immutable_backups: boolean;
  finance_segmentation: boolean;
  remove_local_admin: boolean;
  offline_backup_copy: boolean;
  edr_on_servers: boolean;
}

export interface MetricComparison {
  metric_name: string;
  baseline_value: number;
  remediated_value: number;
  absolute_change: number;
  percentage_change: number;
  unit: string;
  improved: boolean;
  interpretation: string;
}

export interface WhatIfComparisonResponse {
  applied_controls: RemediationControls;
  patient_zero_evaluated: string;
  baseline_blast_radius: BlastRadiusMetrics;
  remediated_blast_radius: BlastRadiusMetrics;
  baseline_ttd: DetectionMetrics;
  remediated_ttd: DetectionMetrics;
  baseline_recovery: RecoveryEstimateResponse;
  remediated_recovery: RecoveryEstimateResponse;
  baseline_maturity: MaturityScoreResponse;
  remediated_maturity: MaturityScoreResponse;
  comparison_summary: MetricComparison[];
}

export interface RemediationCandidate {
  control_key: string;
  name: string;
  description: string;
  implementation_effort: number;
  blast_radius_reduction_pct: number;
  recovery_hours_saved: number;
  maturity_score_increase: number;
  composite_risk_reduction: number;
  roi_score: number;
  rank: number;
}

export interface RemediationRankingResponse {
  formula_documentation: string;
  candidates: RemediationCandidate[];
}

/* Phase 3 ML Detector Types */

export interface BaselineStatusResponse {
  is_recording: boolean;
  session_id?: string;
  monitored_directory?: string;
  duration_seconds?: number;
  window_count?: number;
  event_count?: number;
}

export interface BaselineSessionItem {
  session_id: string;
  created_at: string;
  monitored_directory: string;
  consent_given: number;
  duration_seconds: number;
  window_count: number;
  event_count: number;
  source_type: string;
}

export interface BaselineStatsResponse {
  total_sessions: number;
  total_windows: number;
  total_duration_seconds: number;
  total_events: number;
  sessions: BaselineSessionItem[];
}

export interface TrainModelResponse {
  model_id: string;
  created_at: string;
  schema_version: string;
  training_row_count: number;
  heldout_row_count: number;
  total_baseline_windows: number;
  feature_columns: string[];
  threshold_value: number;
  sensitivity: number;
  random_seed: number;
  contamination: number;
  artifact_filename: string;
}

export interface ConfusionMatrix {
  tp: number;
  fp: number;
  tn: number;
  fn: number;
}

export interface DetectorEvaluationMetrics {
  detection_rate: number;
  false_positive_rate: number;
  precision: number;
  recall: number;
  f1_score: number;
  confusion_matrix: ConfusionMatrix;
  per_stage: Record<string, { detected: boolean; alert_time?: number }>;
  ttd_hours: number;
}

export interface EvaluationResponse {
  eval_id: string;
  created_at: string;
  model_id: string;
  schema_version: string;
  total_test_windows: number;
  heldout_normal_count: number;
  emulator_window_count: number;
  threshold_detector: DetectorEvaluationMetrics;
  isolation_forest_ml: DetectorEvaluationMetrics;
  insufficient_data?: boolean;
}

export interface LiveAlert {
  alert_id: string;
  timestamp: number;
  session_id: string;
  anomaly_score: number;
  threshold_value: number;
  explanations: string[];
  stage_tag: string;
}

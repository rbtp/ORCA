--
-- PostgreSQL database dump
--

\restrict 2NODMaeTeRt1Dlhvo4byDOOa8GVKe3gFFfbtdaP4m8J9pQvfrLraf1JsVaJduZN

-- Dumped from database version 15.19 (Debian 15.19-1.pgdg13+2)
-- Dumped by pg_dump version 15.19 (Debian 15.19-1.pgdg13+2)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;


--
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';


--
-- Name: get_actor_defense_scorecard(text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.get_actor_defense_scorecard(actor_input text) RETURNS TABLE(mitigation_name text, techniques_covered bigint, details text)
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN QUERY
    SELECT 
        m.name, 
        COUNT(DISTINCT t.stix_id) as techniques_covered,
        m.description
    FROM mitre_actors a
    JOIN mitre_relationships r1 ON a.stix_id = r1.source_ref
    JOIN mitre_software s ON r1.target_ref = s.stix_id
    JOIN mitre_relationships r2 ON s.stix_id = r2.source_ref
    JOIN mitre_techniques t ON r2.target_ref = t.stix_id
    JOIN mitre_relationships r3 ON t.stix_id = r3.target_ref
    JOIN mitre_mitigations m ON r3.source_ref = m.stix_id
    WHERE a.name ILIKE actor_input 
      AND r1.relationship_type = 'uses'
      AND r2.relationship_type = 'uses'
      AND r3.relationship_type = 'mitigates'
    GROUP BY m.name, m.description
    ORDER BY techniques_covered DESC;
END;
$$;


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: agent_jobs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_jobs (
    id integer NOT NULL,
    job_id character varying(64) NOT NULL,
    agent_id character varying(64),
    job_type character varying(50) NOT NULL,
    params jsonb NOT NULL,
    status character varying(20) DEFAULT 'PENDING'::character varying,
    created_at timestamp without time zone DEFAULT now(),
    started_at timestamp without time zone,
    completed_at timestamp without time zone,
    summary jsonb
);


--
-- Name: agent_jobs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.agent_jobs_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: agent_jobs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.agent_jobs_id_seq OWNED BY public.agent_jobs.id;


--
-- Name: agent_registrations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_registrations (
    id integer NOT NULL,
    agent_id character varying(64) NOT NULL,
    hostname character varying(255),
    analyst_id integer,
    capabilities jsonb DEFAULT '[]'::jsonb,
    last_seen timestamp without time zone DEFAULT now(),
    registered_at timestamp without time zone DEFAULT now()
);


--
-- Name: agent_registrations_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.agent_registrations_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: agent_registrations_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.agent_registrations_id_seq OWNED BY public.agent_registrations.id;


--
-- Name: analyst_notes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.analyst_notes (
    id integer NOT NULL,
    asset_id integer,
    target_type character varying(50),
    note_text text,
    "timestamp" character varying(50)
);


--
-- Name: analyst_notes_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.analyst_notes_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: analyst_notes_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.analyst_notes_id_seq OWNED BY public.analyst_notes.id;


--
-- Name: artifact_results; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.artifact_results (
    id integer NOT NULL,
    asset_id integer,
    t_code character varying(50),
    verdict character varying(50),
    evidence_summary jsonb,
    evidence_path text,
    evidence_imported boolean DEFAULT false,
    technique_status character varying(20) DEFAULT 'UNCLAIMED'::character varying,
    claimed_by integer,
    claimed_at timestamp without time zone,
    closed_at timestamp without time zone,
    is_fallback boolean DEFAULT false,
    raw_data jsonb,
    ingested_at timestamp without time zone
);


--
-- Name: artifact_results_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.artifact_results_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: artifact_results_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.artifact_results_id_seq OWNED BY public.artifact_results.id;


--
-- Name: asset_evidence; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.asset_evidence (
    id integer NOT NULL,
    asset_id integer,
    t_code text,
    artifact_source text,
    summary text,
    "timestamp" timestamp without time zone,
    raw_data jsonb,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: asset_evidence_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.asset_evidence_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: asset_evidence_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.asset_evidence_id_seq OWNED BY public.asset_evidence.id;


--
-- Name: assets; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.assets (
    id integer NOT NULL,
    case_name character varying(255),
    hostname character varying(255),
    ip character varying(50),
    os text,
    type character varying(50),
    country_focus character varying(255) DEFAULT 'Global'::character varying,
    subnet_mask character varying,
    gateway character varying,
    mac_address character varying,
    os_version character varying,
    form_factor character varying,
    asset_notes text,
    status character varying(50) DEFAULT 'pending'::character varying,
    last_seen timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    analysis_mode character varying(20) DEFAULT 'UNKNOWN'::character varying,
    asset_type character varying(30) DEFAULT 'Workstation'::character varying NOT NULL,
    net_config_text text,
    net_config_filename character varying(500),
    local_dir text
);


--
-- Name: assets_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.assets_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: assets_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.assets_id_seq OWNED BY public.assets.id;


--
-- Name: audit_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.audit_log (
    id integer NOT NULL,
    ts timestamp with time zone DEFAULT now() NOT NULL,
    username text NOT NULL,
    user_initials text,
    action text NOT NULL,
    case_name text,
    asset_id integer,
    asset_hostname text,
    t_code text,
    details text
);


--
-- Name: audit_log_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.audit_log_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: audit_log_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.audit_log_id_seq OWNED BY public.audit_log.id;


--
-- Name: behavioral_jobs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.behavioral_jobs (
    job_id uuid DEFAULT gen_random_uuid() NOT NULL,
    asset_id integer NOT NULL,
    submitted_file text NOT NULL,
    file_path text NOT NULL,
    file_md5 text,
    file_sha256 text,
    file_type text,
    file_size_bytes bigint,
    submitted_by text,
    submitted_at timestamp with time zone DEFAULT now(),
    capa_status text DEFAULT 'pending'::text,
    floss_status text DEFAULT 'pending'::text,
    speakeasy_status text DEFAULT 'pending'::text,
    capa_started_at timestamp with time zone,
    capa_completed_at timestamp with time zone,
    floss_started_at timestamp with time zone,
    floss_completed_at timestamp with time zone,
    speakeasy_started_at timestamp with time zone,
    speakeasy_completed_at timestamp with time zone,
    capa_error text,
    floss_error text,
    speakeasy_error text,
    overall_status text DEFAULT 'running'::text
);


--
-- Name: capa_results; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.capa_results (
    id integer NOT NULL,
    job_id uuid NOT NULL,
    asset_id integer NOT NULL,
    technique_id text NOT NULL,
    technique_name text NOT NULL,
    tactic_name text NOT NULL,
    namespace text,
    severity text,
    raw_result jsonb
);


--
-- Name: capa_results_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.capa_results_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: capa_results_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.capa_results_id_seq OWNED BY public.capa_results.id;


--
-- Name: case_notes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.case_notes (
    id integer NOT NULL,
    case_name character varying(255),
    note_text text NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    author_id integer,
    author_initials character varying(10),
    note_type character varying(10) DEFAULT 'NOTE'::character varying
);


--
-- Name: case_notes_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.case_notes_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: case_notes_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.case_notes_id_seq OWNED BY public.case_notes.id;


--
-- Name: cases; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cases (
    name character varying(255) NOT NULL,
    selected_groups text,
    focus_country text,
    mission_lead text,
    created timestamp without time zone,
    team_name character varying(255),
    support text,
    personnel text,
    map_data jsonb,
    map_links jsonb,
    case_type character varying(20) DEFAULT 'INVESTIGATION'::character varying NOT NULL,
    local_dir text,
    map_background bytea,
    map_background_content_type text
);


--
-- Name: clam_results; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.clam_results (
    id integer NOT NULL,
    asset_id integer NOT NULL,
    scan_path text,
    scanned integer DEFAULT 0,
    infected integer DEFAULT 0,
    threats jsonb DEFAULT '[]'::jsonb,
    scanned_at timestamp without time zone DEFAULT now()
);


--
-- Name: clam_results_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.clam_results_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: clam_results_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.clam_results_id_seq OWNED BY public.clam_results.id;


--
-- Name: discovered_iocs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.discovered_iocs (
    id integer NOT NULL,
    ioc_value text NOT NULL,
    ioc_type text,
    case_name text,
    asset_id integer,
    t_code text,
    note text,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: discovered_iocs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.discovered_iocs_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: discovered_iocs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.discovered_iocs_id_seq OWNED BY public.discovered_iocs.id;


--
-- Name: enrichment_progress; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.enrichment_progress (
    t_code character varying(20) NOT NULL,
    status character varying(20) DEFAULT 'PENDING'::character varying,
    attempt_count integer DEFAULT 0,
    last_attempt timestamp without time zone,
    error_msg text,
    has_analytics boolean DEFAULT false,
    has_vql boolean DEFAULT false
);


--
-- Name: enrichment_staging; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.enrichment_staging (
    id integer NOT NULL,
    t_code character varying(20) NOT NULL,
    live_analysis text,
    dead_disk_analysis text,
    collection_strategy text,
    custom_vql text,
    surgical_yaml text,
    promoted boolean DEFAULT false,
    created_at timestamp without time zone DEFAULT now(),
    promoted_at timestamp without time zone,
    model_used character varying(50)
);


--
-- Name: enrichment_staging_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.enrichment_staging_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: enrichment_staging_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.enrichment_staging_id_seq OWNED BY public.enrichment_staging.id;


--
-- Name: evidence; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.evidence (
    id integer NOT NULL,
    asset_id integer,
    t_code text,
    file_name text,
    file_path text,
    "timestamp" timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    raw_data jsonb
);


--
-- Name: evidence_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.evidence_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: evidence_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.evidence_id_seq OWNED BY public.evidence.id;


--
-- Name: floss_results; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.floss_results (
    id integer NOT NULL,
    job_id uuid NOT NULL,
    asset_id integer NOT NULL,
    string_value text NOT NULL,
    string_type text NOT NULL,
    is_ioc boolean DEFAULT false,
    ioc_type text,
    string_offset bigint
);


--
-- Name: floss_results_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.floss_results_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: floss_results_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.floss_results_id_seq OWNED BY public.floss_results.id;


--
-- Name: group_techniques_mapping; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.group_techniques_mapping (
    group_stix_id text NOT NULL,
    technique_stix_id text NOT NULL
);


--
-- Name: intel_cache; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.intel_cache (
    id integer NOT NULL,
    ioc_value text NOT NULL,
    ioc_type text NOT NULL,
    source text,
    threat_details jsonb,
    last_updated timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: intel_cache_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.intel_cache_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: intel_cache_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.intel_cache_id_seq OWNED BY public.intel_cache.id;


--
-- Name: investigation_intelligence_map; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.investigation_intelligence_map (
    focus_country text,
    threat_group text,
    t_code character varying(50),
    kape_targets text[]
);


--
-- Name: investigation_profiles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.investigation_profiles (
    id integer NOT NULL,
    name character varying(255) NOT NULL,
    tcodes text[] DEFAULT '{}'::text[] NOT NULL,
    created_at timestamp without time zone DEFAULT now(),
    updated_at timestamp without time zone DEFAULT now()
);


--
-- Name: investigation_profiles_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.investigation_profiles_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: investigation_profiles_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.investigation_profiles_id_seq OWNED BY public.investigation_profiles.id;


--
-- Name: ioc_scans; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ioc_scans (
    id integer NOT NULL,
    case_name character varying,
    ioc_value character varying,
    ioc_type character varying,
    hit_count integer,
    status character varying,
    created_at timestamp without time zone
);


--
-- Name: ioc_scans_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ioc_scans_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ioc_scans_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ioc_scans_id_seq OWNED BY public.ioc_scans.id;


--
-- Name: kape_mitre_mapping; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.kape_mitre_mapping (
    t_code character varying(20) NOT NULL,
    kape_targets text[],
    vr_target_name character varying(255)
);


--
-- Name: memory_results; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.memory_results (
    id integer NOT NULL,
    asset_id integer NOT NULL,
    plugin character varying(100) NOT NULL,
    columns jsonb,
    rows jsonb,
    row_count integer DEFAULT 0,
    image_path text,
    scanned_at timestamp without time zone DEFAULT now()
);


--
-- Name: memory_results_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.memory_results_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: memory_results_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.memory_results_id_seq OWNED BY public.memory_results.id;


--
-- Name: memory_sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.memory_sessions (
    id integer NOT NULL,
    asset_id integer NOT NULL,
    session_id character varying(64) NOT NULL,
    profile character varying(20),
    actor character varying(100),
    phase character varying(30) DEFAULT 'DISPATCHED'::character varying,
    plugins_total integer DEFAULT 0,
    plugins_complete integer DEFAULT 0,
    current_plugin character varying(100),
    error text,
    created_at timestamp without time zone DEFAULT now(),
    updated_at timestamp without time zone DEFAULT now()
);


--
-- Name: memory_sessions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.memory_sessions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: memory_sessions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.memory_sessions_id_seq OWNED BY public.memory_sessions.id;


--
-- Name: mft_entries; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mft_entries (
    id bigint NOT NULL,
    asset_id integer NOT NULL,
    entry_num bigint,
    parent_num bigint,
    file_name text,
    full_path text,
    is_dir boolean DEFAULT false,
    in_use boolean DEFAULT true,
    has_ads boolean DEFAULT false,
    si_lt_fn boolean DEFAULT false,
    copied boolean DEFAULT false,
    file_size bigint,
    alt_names jsonb,
    si_created timestamp with time zone,
    si_modified timestamp with time zone,
    si_accessed timestamp with time zone,
    si_rc timestamp with time zone,
    fn_created timestamp with time zone,
    fn_modified timestamp with time zone,
    fn_accessed timestamp with time zone,
    path_lower text GENERATED ALWAYS AS (lower(full_path)) STORED
);


--
-- Name: mft_entries_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mft_entries_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mft_entries_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mft_entries_id_seq OWNED BY public.mft_entries.id;


--
-- Name: mitre_actors; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mitre_actors (
    stix_id text NOT NULL,
    g_code text,
    name text,
    description text,
    aliases text[]
);


--
-- Name: mitre_analytics; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mitre_analytics (
    id integer NOT NULL,
    analytic_code character varying(20) NOT NULL,
    name text NOT NULL,
    description text,
    platforms text[],
    stix_id character varying(100),
    det_code character varying(20),
    log_source_refs jsonb,
    mutable_elements jsonb,
    created_at timestamp without time zone DEFAULT now()
);


--
-- Name: mitre_analytics_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mitre_analytics_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mitre_analytics_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mitre_analytics_id_seq OWNED BY public.mitre_analytics.id;


--
-- Name: mitre_campaigns; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mitre_campaigns (
    id text,
    stix_id text,
    name text,
    description text,
    url text,
    created text,
    last_modified text,
    domain text,
    version double precision,
    associated_campaigns text,
    associated_campaigns_citations text,
    first_seen text,
    first_seen_citation text,
    last_seen text,
    last_seen_citation text,
    contributors text,
    relationship_citations text
);


--
-- Name: mitre_datacomponents; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mitre_datacomponents (
    id text,
    stix_id text,
    name text,
    description text,
    url text,
    created text,
    last_modified text,
    domain text,
    version double precision
);


--
-- Name: mitre_detection_strategies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mitre_detection_strategies (
    id integer NOT NULL,
    det_code character varying(20) NOT NULL,
    name text NOT NULL,
    stix_id character varying(100),
    t_code character varying(20),
    created_at timestamp without time zone DEFAULT now()
);


--
-- Name: mitre_detection_strategies_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mitre_detection_strategies_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mitre_detection_strategies_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mitre_detection_strategies_id_seq OWNED BY public.mitre_detection_strategies.id;


--
-- Name: mitre_groups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mitre_groups (
    id text NOT NULL,
    stix_id text,
    name text,
    description text,
    url text,
    created text,
    last_modified text,
    domain text,
    version double precision,
    contributors text,
    associated_groups text,
    associated_groups_citations text,
    relationship_citations text,
    aliases text[]
);


--
-- Name: mitre_log_sources; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mitre_log_sources (
    analytic_stix_id text,
    analytic_name text,
    data_component_id text,
    data_component_name text,
    log_source_name text,
    channel text
);


--
-- Name: mitre_mitigations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mitre_mitigations (
    stix_id text NOT NULL,
    m_code text,
    name text,
    description text
);


--
-- Name: mitre_relationships; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mitre_relationships (
    id integer NOT NULL,
    stix_id character varying(255),
    source_ref character varying(255),
    target_ref character varying(255),
    relationship_type character varying(100),
    modified_at timestamp without time zone,
    description text
);


--
-- Name: mitre_relationships_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mitre_relationships_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mitre_relationships_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mitre_relationships_id_seq OWNED BY public.mitre_relationships.id;


--
-- Name: mitre_software; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mitre_software (
    stix_id character varying(255) NOT NULL,
    s_code character varying(50),
    name character varying(255) NOT NULL,
    description text,
    software_type character varying(50),
    platforms jsonb,
    modified_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: mitre_strategy_analytic_map; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mitre_strategy_analytic_map (
    strategy_stix_id text,
    strategy_name text,
    analytic_stix_id text,
    analytic_name text
);


--
-- Name: mitre_tactics; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mitre_tactics (
    id text NOT NULL,
    stix_id text,
    name text,
    description text,
    url text,
    created text,
    last_modified text,
    domain text,
    version double precision,
    shortname character varying(100) DEFAULT NULL::character varying
);


--
-- Name: mitre_techniques; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mitre_techniques (
    stix_id character varying(255) NOT NULL,
    t_code character varying(50) NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    platforms jsonb,
    tactic character varying(100),
    is_subtechnique boolean,
    modified_at timestamp without time zone,
    kape_targets text,
    detection_notes text,
    parent_t_code character varying(20) DEFAULT NULL::character varying,
    is_deprecated boolean DEFAULT false,
    is_revoked boolean DEFAULT false
);


--
-- Name: mount_sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mount_sessions (
    id integer NOT NULL,
    asset_id integer NOT NULL,
    image_path text NOT NULL,
    device_number character varying(20),
    drive_letter character varying(5),
    physical_drive character varying(50),
    provider character varying(20),
    status character varying(20) DEFAULT 'MOUNTED'::character varying,
    mounted_at timestamp without time zone DEFAULT now(),
    dismounted_at timestamp without time zone
);


--
-- Name: mount_sessions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mount_sessions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mount_sessions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mount_sessions_id_seq OWNED BY public.mount_sessions.id;


--
-- Name: network_links; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.network_links (
    id integer NOT NULL,
    source_id integer NOT NULL,
    target_id integer NOT NULL,
    link_type character varying(20) DEFAULT 'Wired'::character varying,
    source_iface character varying(50),
    source_ip character varying(45),
    target_iface character varying(50),
    target_ip character varying(45),
    vlan integer DEFAULT 1,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: network_links_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.network_links_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: network_links_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.network_links_id_seq OWNED BY public.network_links.id;


--
-- Name: orca_vql_mappings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.orca_vql_mappings (
    orca_name text NOT NULL,
    vr_artifact text,
    vql_query text,
    confidence text,
    t_code character varying(20)
);


--
-- Name: package_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.package_tokens (
    token uuid DEFAULT gen_random_uuid() NOT NULL,
    asset_id integer NOT NULL,
    case_name character varying(255) NOT NULL,
    created_by integer,
    created_at timestamp without time zone DEFAULT now(),
    expires_at timestamp without time zone NOT NULL,
    revoked boolean DEFAULT false,
    revoked_at timestamp without time zone,
    technique_count integer DEFAULT 0,
    techniques_received integer DEFAULT 0,
    completed_at timestamp without time zone
);


--
-- Name: ref_artifact_library; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ref_artifact_library (
    t_code character varying(30) NOT NULL,
    name character varying(255),
    os character varying(50),
    priority character varying(50),
    analysis_steps text,
    id integer NOT NULL,
    collection_strategy text,
    live_analysis text,
    dead_disk_analysis text,
    custom_vql text,
    surgical_yaml text,
    updated_at timestamp without time zone DEFAULT now()
);


--
-- Name: ref_artifact_library_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ref_artifact_library_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ref_artifact_library_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ref_artifact_library_id_seq OWNED BY public.ref_artifact_library.id;


--
-- Name: ref_ioc_library; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ref_ioc_library (
    id integer NOT NULL,
    indicator_type character varying(20),
    value text NOT NULL,
    threat_actor character varying(100),
    severity character varying(20) DEFAULT 'HIGH'::character varying,
    description text,
    added_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: ref_ioc_library_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ref_ioc_library_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ref_ioc_library_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ref_ioc_library_id_seq OWNED BY public.ref_ioc_library.id;


--
-- Name: speakeasy_results; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.speakeasy_results (
    id integer NOT NULL,
    job_id uuid NOT NULL,
    asset_id integer NOT NULL,
    result_type text NOT NULL,
    entry_point integer DEFAULT 0,
    func_name text,
    args jsonb,
    ret_val text,
    pc text,
    protocol text,
    host text,
    port integer,
    url text,
    raw_entry jsonb
);


--
-- Name: speakeasy_results_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.speakeasy_results_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: speakeasy_results_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.speakeasy_results_id_seq OWNED BY public.speakeasy_results.id;


--
-- Name: tcode_notes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tcode_notes (
    id integer NOT NULL,
    asset_id integer NOT NULL,
    t_code character varying(20) NOT NULL,
    note_text text NOT NULL,
    note_type character varying(10) DEFAULT 'NOTE'::character varying,
    created_at timestamp without time zone DEFAULT now(),
    author_id integer,
    author_initials character varying(10)
);


--
-- Name: tcode_notes_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.tcode_notes_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: tcode_notes_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.tcode_notes_id_seq OWNED BY public.tcode_notes.id;


--
-- Name: technique_locks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.technique_locks (
    id integer NOT NULL,
    asset_id integer NOT NULL,
    t_code character varying(20) NOT NULL,
    locked_by integer NOT NULL,
    locked_at timestamp without time zone DEFAULT now(),
    expires_at timestamp without time zone DEFAULT (now() + '00:30:00'::interval)
);


--
-- Name: technique_locks_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.technique_locks_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: technique_locks_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.technique_locks_id_seq OWNED BY public.technique_locks.id;


--
-- Name: threat_attribution; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.threat_attribution (
    id integer NOT NULL,
    group_name character varying(255),
    attribution character varying(255),
    is_static boolean
);


--
-- Name: threat_attribution_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.threat_attribution_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: threat_attribution_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.threat_attribution_id_seq OWNED BY public.threat_attribution.id;


--
-- Name: tool_locks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tool_locks (
    id integer NOT NULL,
    asset_id integer NOT NULL,
    tool_name character varying(30) NOT NULL,
    locked_by integer NOT NULL,
    locked_at timestamp without time zone DEFAULT now(),
    expires_at timestamp without time zone DEFAULT (now() + '02:00:00'::interval)
);


--
-- Name: tool_locks_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.tool_locks_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: tool_locks_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.tool_locks_id_seq OWNED BY public.tool_locks.id;


--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    id integer NOT NULL,
    username character varying(50) NOT NULL,
    password_hash text NOT NULL,
    initials character varying(5) NOT NULL,
    role character varying(20) DEFAULT 'analyst'::character varying,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: users_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.users_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: users_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.users_id_seq OWNED BY public.users.id;


--
-- Name: v_attribution_chain; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.v_attribution_chain AS
 SELECT a.name AS actor_name,
    a.g_code AS actor_id,
    s.name AS software_name,
    s.s_code AS software_id,
    t.t_code AS technique_id,
    t.name AS technique_name,
    t.tactic
   FROM ((((public.mitre_actors a
     JOIN public.mitre_relationships r1 ON ((a.stix_id = (r1.source_ref)::text)))
     JOIN public.mitre_software s ON (((r1.target_ref)::text = (s.stix_id)::text)))
     JOIN public.mitre_relationships r2 ON (((s.stix_id)::text = (r2.source_ref)::text)))
     JOIN public.mitre_techniques t ON (((r2.target_ref)::text = (t.stix_id)::text)))
  WHERE (((r1.relationship_type)::text = 'uses'::text) AND ((r2.relationship_type)::text = 'uses'::text));


--
-- Name: v_defensive_strategy; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.v_defensive_strategy AS
 SELECT a.name AS actor_name,
    t.t_code AS technique_id,
    t.name AS technique_name,
    m.m_code AS mitigation_id,
    m.name AS mitigation_name,
    m.description AS mitigation_details
   FROM ((((((public.mitre_actors a
     JOIN public.mitre_relationships r1 ON ((a.stix_id = (r1.source_ref)::text)))
     JOIN public.mitre_software s ON (((r1.target_ref)::text = (s.stix_id)::text)))
     JOIN public.mitre_relationships r2 ON (((s.stix_id)::text = (r2.source_ref)::text)))
     JOIN public.mitre_techniques t ON (((r2.target_ref)::text = (t.stix_id)::text)))
     JOIN public.mitre_relationships r3 ON (((t.stix_id)::text = (r3.target_ref)::text)))
     JOIN public.mitre_mitigations m ON (((r3.source_ref)::text = m.stix_id)))
  WHERE (((r1.relationship_type)::text = 'uses'::text) AND ((r2.relationship_type)::text = 'uses'::text) AND ((r3.relationship_type)::text = 'mitigates'::text));


--
-- Name: v_software_threat_profiles; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.v_software_threat_profiles AS
 SELECT s.s_code,
    s.name AS software_name,
    t.t_code,
    t.name AS technique_name,
    t.tactic,
    r.description AS implementation_details
   FROM ((public.mitre_software s
     JOIN public.mitre_relationships r ON (((s.stix_id)::text = (r.source_ref)::text)))
     JOIN public.mitre_techniques t ON (((r.target_ref)::text = (t.stix_id)::text)))
  WHERE ((r.relationship_type)::text = 'uses'::text);


--
-- Name: vuln_results; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vuln_results (
    id integer NOT NULL,
    asset_id integer NOT NULL,
    cve_id character varying(50),
    severity character varying(20),
    package character varying(255),
    version character varying(100),
    fix_version character varying(100),
    fix_state character varying(50),
    sbom_path text,
    vuln_path text,
    scanned_at timestamp without time zone DEFAULT now()
);


--
-- Name: vuln_results_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.vuln_results_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: vuln_results_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.vuln_results_id_seq OWNED BY public.vuln_results.id;


--
-- Name: agent_jobs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_jobs ALTER COLUMN id SET DEFAULT nextval('public.agent_jobs_id_seq'::regclass);


--
-- Name: agent_registrations id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_registrations ALTER COLUMN id SET DEFAULT nextval('public.agent_registrations_id_seq'::regclass);


--
-- Name: analyst_notes id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.analyst_notes ALTER COLUMN id SET DEFAULT nextval('public.analyst_notes_id_seq'::regclass);


--
-- Name: artifact_results id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.artifact_results ALTER COLUMN id SET DEFAULT nextval('public.artifact_results_id_seq'::regclass);


--
-- Name: asset_evidence id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.asset_evidence ALTER COLUMN id SET DEFAULT nextval('public.asset_evidence_id_seq'::regclass);


--
-- Name: assets id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.assets ALTER COLUMN id SET DEFAULT nextval('public.assets_id_seq'::regclass);


--
-- Name: audit_log id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_log ALTER COLUMN id SET DEFAULT nextval('public.audit_log_id_seq'::regclass);


--
-- Name: capa_results id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.capa_results ALTER COLUMN id SET DEFAULT nextval('public.capa_results_id_seq'::regclass);


--
-- Name: case_notes id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_notes ALTER COLUMN id SET DEFAULT nextval('public.case_notes_id_seq'::regclass);


--
-- Name: clam_results id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.clam_results ALTER COLUMN id SET DEFAULT nextval('public.clam_results_id_seq'::regclass);


--
-- Name: discovered_iocs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.discovered_iocs ALTER COLUMN id SET DEFAULT nextval('public.discovered_iocs_id_seq'::regclass);


--
-- Name: enrichment_staging id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.enrichment_staging ALTER COLUMN id SET DEFAULT nextval('public.enrichment_staging_id_seq'::regclass);


--
-- Name: evidence id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.evidence ALTER COLUMN id SET DEFAULT nextval('public.evidence_id_seq'::regclass);


--
-- Name: floss_results id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.floss_results ALTER COLUMN id SET DEFAULT nextval('public.floss_results_id_seq'::regclass);


--
-- Name: intel_cache id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.intel_cache ALTER COLUMN id SET DEFAULT nextval('public.intel_cache_id_seq'::regclass);


--
-- Name: investigation_profiles id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.investigation_profiles ALTER COLUMN id SET DEFAULT nextval('public.investigation_profiles_id_seq'::regclass);


--
-- Name: ioc_scans id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_scans ALTER COLUMN id SET DEFAULT nextval('public.ioc_scans_id_seq'::regclass);


--
-- Name: memory_results id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.memory_results ALTER COLUMN id SET DEFAULT nextval('public.memory_results_id_seq'::regclass);


--
-- Name: memory_sessions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.memory_sessions ALTER COLUMN id SET DEFAULT nextval('public.memory_sessions_id_seq'::regclass);


--
-- Name: mft_entries id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mft_entries ALTER COLUMN id SET DEFAULT nextval('public.mft_entries_id_seq'::regclass);


--
-- Name: mitre_analytics id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mitre_analytics ALTER COLUMN id SET DEFAULT nextval('public.mitre_analytics_id_seq'::regclass);


--
-- Name: mitre_detection_strategies id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mitre_detection_strategies ALTER COLUMN id SET DEFAULT nextval('public.mitre_detection_strategies_id_seq'::regclass);


--
-- Name: mitre_relationships id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mitre_relationships ALTER COLUMN id SET DEFAULT nextval('public.mitre_relationships_id_seq'::regclass);


--
-- Name: mount_sessions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mount_sessions ALTER COLUMN id SET DEFAULT nextval('public.mount_sessions_id_seq'::regclass);


--
-- Name: network_links id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.network_links ALTER COLUMN id SET DEFAULT nextval('public.network_links_id_seq'::regclass);


--
-- Name: ref_artifact_library id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ref_artifact_library ALTER COLUMN id SET DEFAULT nextval('public.ref_artifact_library_id_seq'::regclass);


--
-- Name: ref_ioc_library id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ref_ioc_library ALTER COLUMN id SET DEFAULT nextval('public.ref_ioc_library_id_seq'::regclass);


--
-- Name: speakeasy_results id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.speakeasy_results ALTER COLUMN id SET DEFAULT nextval('public.speakeasy_results_id_seq'::regclass);


--
-- Name: tcode_notes id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tcode_notes ALTER COLUMN id SET DEFAULT nextval('public.tcode_notes_id_seq'::regclass);


--
-- Name: technique_locks id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.technique_locks ALTER COLUMN id SET DEFAULT nextval('public.technique_locks_id_seq'::regclass);


--
-- Name: threat_attribution id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_attribution ALTER COLUMN id SET DEFAULT nextval('public.threat_attribution_id_seq'::regclass);


--
-- Name: tool_locks id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tool_locks ALTER COLUMN id SET DEFAULT nextval('public.tool_locks_id_seq'::regclass);


--
-- Name: users id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users ALTER COLUMN id SET DEFAULT nextval('public.users_id_seq'::regclass);


--
-- Name: vuln_results id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vuln_results ALTER COLUMN id SET DEFAULT nextval('public.vuln_results_id_seq'::regclass);


--
-- Name: agent_jobs agent_jobs_job_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_jobs
    ADD CONSTRAINT agent_jobs_job_id_key UNIQUE (job_id);


--
-- Name: agent_jobs agent_jobs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_jobs
    ADD CONSTRAINT agent_jobs_pkey PRIMARY KEY (id);


--
-- Name: agent_registrations agent_registrations_agent_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_registrations
    ADD CONSTRAINT agent_registrations_agent_id_key UNIQUE (agent_id);


--
-- Name: agent_registrations agent_registrations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_registrations
    ADD CONSTRAINT agent_registrations_pkey PRIMARY KEY (id);


--
-- Name: analyst_notes analyst_notes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.analyst_notes
    ADD CONSTRAINT analyst_notes_pkey PRIMARY KEY (id);


--
-- Name: artifact_results artifact_results_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.artifact_results
    ADD CONSTRAINT artifact_results_pkey PRIMARY KEY (id);


--
-- Name: asset_evidence asset_evidence_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.asset_evidence
    ADD CONSTRAINT asset_evidence_pkey PRIMARY KEY (id);


--
-- Name: assets assets_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.assets
    ADD CONSTRAINT assets_pkey PRIMARY KEY (id);


--
-- Name: audit_log audit_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT audit_log_pkey PRIMARY KEY (id);


--
-- Name: behavioral_jobs behavioral_jobs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.behavioral_jobs
    ADD CONSTRAINT behavioral_jobs_pkey PRIMARY KEY (job_id);


--
-- Name: capa_results capa_results_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.capa_results
    ADD CONSTRAINT capa_results_pkey PRIMARY KEY (id);


--
-- Name: case_notes case_notes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_notes
    ADD CONSTRAINT case_notes_pkey PRIMARY KEY (id);


--
-- Name: cases cases_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cases
    ADD CONSTRAINT cases_pkey PRIMARY KEY (name);


--
-- Name: clam_results clam_results_asset_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.clam_results
    ADD CONSTRAINT clam_results_asset_id_key UNIQUE (asset_id);


--
-- Name: clam_results clam_results_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.clam_results
    ADD CONSTRAINT clam_results_pkey PRIMARY KEY (id);


--
-- Name: discovered_iocs discovered_iocs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.discovered_iocs
    ADD CONSTRAINT discovered_iocs_pkey PRIMARY KEY (id);


--
-- Name: enrichment_progress enrichment_progress_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.enrichment_progress
    ADD CONSTRAINT enrichment_progress_pkey PRIMARY KEY (t_code);


--
-- Name: enrichment_staging enrichment_staging_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.enrichment_staging
    ADD CONSTRAINT enrichment_staging_pkey PRIMARY KEY (id);


--
-- Name: enrichment_staging enrichment_staging_t_code_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.enrichment_staging
    ADD CONSTRAINT enrichment_staging_t_code_key UNIQUE (t_code);


--
-- Name: evidence evidence_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.evidence
    ADD CONSTRAINT evidence_pkey PRIMARY KEY (id);


--
-- Name: floss_results floss_results_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.floss_results
    ADD CONSTRAINT floss_results_pkey PRIMARY KEY (id);


--
-- Name: group_techniques_mapping group_techniques_mapping_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.group_techniques_mapping
    ADD CONSTRAINT group_techniques_mapping_pkey PRIMARY KEY (group_stix_id, technique_stix_id);


--
-- Name: intel_cache intel_cache_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.intel_cache
    ADD CONSTRAINT intel_cache_pkey PRIMARY KEY (id);


--
-- Name: investigation_profiles investigation_profiles_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.investigation_profiles
    ADD CONSTRAINT investigation_profiles_name_key UNIQUE (name);


--
-- Name: investigation_profiles investigation_profiles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.investigation_profiles
    ADD CONSTRAINT investigation_profiles_pkey PRIMARY KEY (id);


--
-- Name: ioc_scans ioc_scans_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_scans
    ADD CONSTRAINT ioc_scans_pkey PRIMARY KEY (id);


--
-- Name: kape_mitre_mapping kape_mitre_mapping_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.kape_mitre_mapping
    ADD CONSTRAINT kape_mitre_mapping_pkey PRIMARY KEY (t_code);


--
-- Name: memory_results memory_results_asset_id_plugin_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.memory_results
    ADD CONSTRAINT memory_results_asset_id_plugin_key UNIQUE (asset_id, plugin);


--
-- Name: memory_results memory_results_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.memory_results
    ADD CONSTRAINT memory_results_pkey PRIMARY KEY (id);


--
-- Name: memory_sessions memory_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.memory_sessions
    ADD CONSTRAINT memory_sessions_pkey PRIMARY KEY (id);


--
-- Name: memory_sessions memory_sessions_session_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.memory_sessions
    ADD CONSTRAINT memory_sessions_session_id_key UNIQUE (session_id);


--
-- Name: mft_entries mft_entries_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mft_entries
    ADD CONSTRAINT mft_entries_pkey PRIMARY KEY (id);


--
-- Name: mitre_actors mitre_actors_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mitre_actors
    ADD CONSTRAINT mitre_actors_name_key UNIQUE (name);


--
-- Name: mitre_actors mitre_actors_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mitre_actors
    ADD CONSTRAINT mitre_actors_pkey PRIMARY KEY (stix_id);


--
-- Name: mitre_analytics mitre_analytics_analytic_code_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mitre_analytics
    ADD CONSTRAINT mitre_analytics_analytic_code_key UNIQUE (analytic_code);


--
-- Name: mitre_analytics mitre_analytics_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mitre_analytics
    ADD CONSTRAINT mitre_analytics_pkey PRIMARY KEY (id);


--
-- Name: mitre_analytics mitre_analytics_stix_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mitre_analytics
    ADD CONSTRAINT mitre_analytics_stix_id_key UNIQUE (stix_id);


--
-- Name: mitre_detection_strategies mitre_detection_strategies_det_code_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mitre_detection_strategies
    ADD CONSTRAINT mitre_detection_strategies_det_code_key UNIQUE (det_code);


--
-- Name: mitre_detection_strategies mitre_detection_strategies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mitre_detection_strategies
    ADD CONSTRAINT mitre_detection_strategies_pkey PRIMARY KEY (id);


--
-- Name: mitre_detection_strategies mitre_detection_strategies_stix_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mitre_detection_strategies
    ADD CONSTRAINT mitre_detection_strategies_stix_id_key UNIQUE (stix_id);


--
-- Name: mitre_groups mitre_groups_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mitre_groups
    ADD CONSTRAINT mitre_groups_pkey PRIMARY KEY (id);


--
-- Name: mitre_mitigations mitre_mitigations_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mitre_mitigations
    ADD CONSTRAINT mitre_mitigations_name_key UNIQUE (name);


--
-- Name: mitre_mitigations mitre_mitigations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mitre_mitigations
    ADD CONSTRAINT mitre_mitigations_pkey PRIMARY KEY (stix_id);


--
-- Name: mitre_relationships mitre_relationships_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mitre_relationships
    ADD CONSTRAINT mitre_relationships_pkey PRIMARY KEY (id);


--
-- Name: mitre_relationships mitre_relationships_stix_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mitre_relationships
    ADD CONSTRAINT mitre_relationships_stix_id_key UNIQUE (stix_id);


--
-- Name: mitre_software mitre_software_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mitre_software
    ADD CONSTRAINT mitre_software_pkey PRIMARY KEY (stix_id);


--
-- Name: mitre_tactics mitre_tactics_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mitre_tactics
    ADD CONSTRAINT mitre_tactics_pkey PRIMARY KEY (id);


--
-- Name: mitre_techniques mitre_techniques_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mitre_techniques
    ADD CONSTRAINT mitre_techniques_pkey PRIMARY KEY (stix_id);


--
-- Name: mount_sessions mount_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mount_sessions
    ADD CONSTRAINT mount_sessions_pkey PRIMARY KEY (id);


--
-- Name: network_links network_links_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.network_links
    ADD CONSTRAINT network_links_pkey PRIMARY KEY (id);


--
-- Name: orca_vql_mappings orca_vql_mappings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.orca_vql_mappings
    ADD CONSTRAINT orca_vql_mappings_pkey PRIMARY KEY (orca_name);


--
-- Name: package_tokens package_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.package_tokens
    ADD CONSTRAINT package_tokens_pkey PRIMARY KEY (token);


--
-- Name: ref_artifact_library ref_artifact_library_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ref_artifact_library
    ADD CONSTRAINT ref_artifact_library_pkey PRIMARY KEY (id);


--
-- Name: ref_artifact_library ref_artifact_library_t_code_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ref_artifact_library
    ADD CONSTRAINT ref_artifact_library_t_code_key UNIQUE (t_code);


--
-- Name: ref_ioc_library ref_ioc_library_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ref_ioc_library
    ADD CONSTRAINT ref_ioc_library_pkey PRIMARY KEY (id);


--
-- Name: ref_ioc_library ref_ioc_library_value_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ref_ioc_library
    ADD CONSTRAINT ref_ioc_library_value_key UNIQUE (value);


--
-- Name: speakeasy_results speakeasy_results_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.speakeasy_results
    ADD CONSTRAINT speakeasy_results_pkey PRIMARY KEY (id);


--
-- Name: tcode_notes tcode_notes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tcode_notes
    ADD CONSTRAINT tcode_notes_pkey PRIMARY KEY (id);


--
-- Name: technique_locks technique_locks_asset_id_t_code_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.technique_locks
    ADD CONSTRAINT technique_locks_asset_id_t_code_key UNIQUE (asset_id, t_code);


--
-- Name: technique_locks technique_locks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.technique_locks
    ADD CONSTRAINT technique_locks_pkey PRIMARY KEY (id);


--
-- Name: threat_attribution threat_attribution_group_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_attribution
    ADD CONSTRAINT threat_attribution_group_name_key UNIQUE (group_name);


--
-- Name: threat_attribution threat_attribution_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_attribution
    ADD CONSTRAINT threat_attribution_pkey PRIMARY KEY (id);


--
-- Name: tool_locks tool_locks_asset_id_tool_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tool_locks
    ADD CONSTRAINT tool_locks_asset_id_tool_name_key UNIQUE (asset_id, tool_name);


--
-- Name: tool_locks tool_locks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tool_locks
    ADD CONSTRAINT tool_locks_pkey PRIMARY KEY (id);


--
-- Name: artifact_results unique_asset_tcode; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.artifact_results
    ADD CONSTRAINT unique_asset_tcode UNIQUE (asset_id, t_code);


--
-- Name: discovered_iocs unique_ioc_per_case; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.discovered_iocs
    ADD CONSTRAINT unique_ioc_per_case UNIQUE (ioc_value, case_name);


--
-- Name: mitre_software unique_software_name; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mitre_software
    ADD CONSTRAINT unique_software_name UNIQUE (name);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: users users_username_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_username_key UNIQUE (username);


--
-- Name: vuln_results vuln_results_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vuln_results
    ADD CONSTRAINT vuln_results_pkey PRIMARY KEY (id);


--
-- Name: idx_analytics_det_code; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_analytics_det_code ON public.mitre_analytics USING btree (det_code);


--
-- Name: idx_asset_focus; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_asset_focus ON public.assets USING btree (country_focus);


--
-- Name: idx_audit_log_asset; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_log_asset ON public.audit_log USING btree (asset_id);


--
-- Name: idx_audit_log_case; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_log_case ON public.audit_log USING btree (case_name);


--
-- Name: idx_audit_log_ts; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_log_ts ON public.audit_log USING btree (ts);


--
-- Name: idx_capa_results_asset; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_capa_results_asset ON public.capa_results USING btree (asset_id);


--
-- Name: idx_capa_results_job; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_capa_results_job ON public.capa_results USING btree (job_id);


--
-- Name: idx_capa_results_technique; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_capa_results_technique ON public.capa_results USING btree (technique_id);


--
-- Name: idx_clam_results_asset_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_clam_results_asset_id ON public.clam_results USING btree (asset_id);


--
-- Name: idx_det_strategies_t_code; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_det_strategies_t_code ON public.mitre_detection_strategies USING btree (t_code);


--
-- Name: idx_evidence_asset_tcode; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_evidence_asset_tcode ON public.evidence USING btree (asset_id, t_code);


--
-- Name: idx_floss_results_asset; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_floss_results_asset ON public.floss_results USING btree (asset_id);


--
-- Name: idx_floss_results_ioc; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_floss_results_ioc ON public.floss_results USING btree (job_id, is_ioc) WHERE (is_ioc = true);


--
-- Name: idx_floss_results_job; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_floss_results_job ON public.floss_results USING btree (job_id);


--
-- Name: idx_investigation_country; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_investigation_country ON public.investigation_intelligence_map USING btree (focus_country);


--
-- Name: idx_ioc_value; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_value ON public.intel_cache USING btree (ioc_value);


--
-- Name: idx_kape_mapping_tcode; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_kape_mapping_tcode ON public.kape_mitre_mapping USING btree (t_code);


--
-- Name: idx_memory_results_asset_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_memory_results_asset_id ON public.memory_results USING btree (asset_id);


--
-- Name: idx_memory_sessions_asset_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_memory_sessions_asset_id ON public.memory_sessions USING btree (asset_id);


--
-- Name: idx_mft_asset; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mft_asset ON public.mft_entries USING btree (asset_id);


--
-- Name: idx_mft_asset_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mft_asset_created ON public.mft_entries USING btree (asset_id, si_created DESC);


--
-- Name: idx_mft_asset_inuse; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mft_asset_inuse ON public.mft_entries USING btree (asset_id, in_use);


--
-- Name: idx_mft_asset_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mft_asset_name ON public.mft_entries USING btree (asset_id, file_name);


--
-- Name: idx_mft_asset_path; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mft_asset_path ON public.mft_entries USING btree (asset_id, path_lower);


--
-- Name: idx_mft_deleted; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mft_deleted ON public.mft_entries USING btree (asset_id, in_use) WHERE (in_use = false);


--
-- Name: idx_mft_timestomp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mft_timestomp ON public.mft_entries USING btree (asset_id, si_lt_fn) WHERE (si_lt_fn = true);


--
-- Name: idx_mitre_rel_source; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mitre_rel_source ON public.mitre_relationships USING btree (source_ref);


--
-- Name: idx_mitre_rel_target; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mitre_rel_target ON public.mitre_relationships USING btree (target_ref);


--
-- Name: idx_package_tokens_asset_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_package_tokens_asset_id ON public.package_tokens USING btree (asset_id);


--
-- Name: idx_package_tokens_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_package_tokens_expires_at ON public.package_tokens USING btree (expires_at);


--
-- Name: idx_speakeasy_results_asset; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_speakeasy_results_asset ON public.speakeasy_results USING btree (asset_id);


--
-- Name: idx_speakeasy_results_job; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_speakeasy_results_job ON public.speakeasy_results USING btree (job_id);


--
-- Name: idx_speakeasy_results_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_speakeasy_results_type ON public.speakeasy_results USING btree (job_id, result_type);


--
-- Name: idx_techniques_parent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_techniques_parent ON public.mitre_techniques USING btree (parent_t_code);


--
-- Name: idx_techniques_platforms; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_techniques_platforms ON public.mitre_techniques USING gin (platforms);


--
-- Name: ix_ioc_scans_ioc_value; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_ioc_scans_ioc_value ON public.ioc_scans USING btree (ioc_value);


--
-- Name: ix_mitre_relationships_source_ref; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_mitre_relationships_source_ref ON public.mitre_relationships USING btree (source_ref);


--
-- Name: ix_mitre_relationships_target_ref; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_mitre_relationships_target_ref ON public.mitre_relationships USING btree (target_ref);


--
-- Name: ix_mitre_software_s_code; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_mitre_software_s_code ON public.mitre_software USING btree (s_code);


--
-- Name: ix_mitre_techniques_t_code; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_mitre_techniques_t_code ON public.mitre_techniques USING btree (t_code);


--
-- Name: ix_mitre_techniques_tactic; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_mitre_techniques_tactic ON public.mitre_techniques USING btree (tactic);


--
-- Name: agent_jobs agent_jobs_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_jobs
    ADD CONSTRAINT agent_jobs_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agent_registrations(agent_id);


--
-- Name: agent_registrations agent_registrations_analyst_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_registrations
    ADD CONSTRAINT agent_registrations_analyst_id_fkey FOREIGN KEY (analyst_id) REFERENCES public.users(id);


--
-- Name: analyst_notes analyst_notes_asset_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.analyst_notes
    ADD CONSTRAINT analyst_notes_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.assets(id) ON DELETE CASCADE;


--
-- Name: artifact_results artifact_results_asset_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.artifact_results
    ADD CONSTRAINT artifact_results_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.assets(id);


--
-- Name: artifact_results artifact_results_claimed_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.artifact_results
    ADD CONSTRAINT artifact_results_claimed_by_fkey FOREIGN KEY (claimed_by) REFERENCES public.users(id);


--
-- Name: asset_evidence asset_evidence_asset_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.asset_evidence
    ADD CONSTRAINT asset_evidence_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.assets(id);


--
-- Name: assets assets_case_name_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.assets
    ADD CONSTRAINT assets_case_name_fkey FOREIGN KEY (case_name) REFERENCES public.cases(name) ON DELETE CASCADE;


--
-- Name: behavioral_jobs behavioral_jobs_asset_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.behavioral_jobs
    ADD CONSTRAINT behavioral_jobs_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.assets(id) ON DELETE CASCADE;


--
-- Name: capa_results capa_results_job_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.capa_results
    ADD CONSTRAINT capa_results_job_id_fkey FOREIGN KEY (job_id) REFERENCES public.behavioral_jobs(job_id) ON DELETE CASCADE;


--
-- Name: case_notes case_notes_author_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_notes
    ADD CONSTRAINT case_notes_author_id_fkey FOREIGN KEY (author_id) REFERENCES public.users(id);


--
-- Name: case_notes case_notes_case_name_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_notes
    ADD CONSTRAINT case_notes_case_name_fkey FOREIGN KEY (case_name) REFERENCES public.cases(name) ON DELETE CASCADE;


--
-- Name: evidence evidence_asset_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.evidence
    ADD CONSTRAINT evidence_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.assets(id);


--
-- Name: floss_results floss_results_job_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.floss_results
    ADD CONSTRAINT floss_results_job_id_fkey FOREIGN KEY (job_id) REFERENCES public.behavioral_jobs(job_id) ON DELETE CASCADE;


--
-- Name: ioc_scans ioc_scans_case_name_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_scans
    ADD CONSTRAINT ioc_scans_case_name_fkey FOREIGN KEY (case_name) REFERENCES public.cases(name);


--
-- Name: network_links network_links_source_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.network_links
    ADD CONSTRAINT network_links_source_id_fkey FOREIGN KEY (source_id) REFERENCES public.assets(id) ON DELETE CASCADE;


--
-- Name: network_links network_links_target_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.network_links
    ADD CONSTRAINT network_links_target_id_fkey FOREIGN KEY (target_id) REFERENCES public.assets(id) ON DELETE CASCADE;


--
-- Name: speakeasy_results speakeasy_results_job_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.speakeasy_results
    ADD CONSTRAINT speakeasy_results_job_id_fkey FOREIGN KEY (job_id) REFERENCES public.behavioral_jobs(job_id) ON DELETE CASCADE;


--
-- Name: tcode_notes tcode_notes_author_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tcode_notes
    ADD CONSTRAINT tcode_notes_author_id_fkey FOREIGN KEY (author_id) REFERENCES public.users(id);


--
-- Name: technique_locks technique_locks_asset_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.technique_locks
    ADD CONSTRAINT technique_locks_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.assets(id) ON DELETE CASCADE;


--
-- Name: technique_locks technique_locks_locked_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.technique_locks
    ADD CONSTRAINT technique_locks_locked_by_fkey FOREIGN KEY (locked_by) REFERENCES public.users(id);


--
-- Name: tool_locks tool_locks_asset_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tool_locks
    ADD CONSTRAINT tool_locks_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.assets(id) ON DELETE CASCADE;


--
-- Name: tool_locks tool_locks_locked_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tool_locks
    ADD CONSTRAINT tool_locks_locked_by_fkey FOREIGN KEY (locked_by) REFERENCES public.users(id);


--
-- PostgreSQL database dump complete
--

\unrestrict 2NODMaeTeRt1Dlhvo4byDOOa8GVKe3gFFfbtdaP4m8J9pQvfrLraf1JsVaJduZN


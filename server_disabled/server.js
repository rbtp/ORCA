const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const app = express();

// 1. Connection to your Docker Database
const pool = new Pool({
  user: 'postgres',
  host: '127.0.0.1',
  database: 'orca_db',
  password: 'password', // Matches your Docker ENV
  port: 5432,
});

app.use(cors()); 
app.use(express.json());

// --- NEW: AGGREGATION ROUTE ---
app.post('/api/aggregate-intel', async (req, res) => {
  const { countries } = req.body; // e.g. ['China', 'Russia']
  
  try {
    // This query finds all groups belonging to the selected countries,
    // then finds all techniques those groups use, and returns a unique list.
    const query = `
      SELECT DISTINCT ON (t.t_code) 
        t.t_code, 
        t.name, 
        t.description, 
        t.tactic
      FROM mitre_techniques t
      JOIN mitre_relationships r ON t.stix_id = r.target_ref
      JOIN mitre_groups g ON r.source_ref = g.stix_id
      WHERE g.country = ANY($1) 
        AND r.relationship_type = 'uses'
      ORDER BY t.t_code ASC;
    `;
    
    const result = await pool.query(query, [countries]);
    
    console.log(`[ORCA_AGGREGATOR] Merged landscape for ${countries.join(', ')}: ${result.rowCount} unique techniques found.`);
    
    res.json({ techniques: result.rows });
  } catch (err) {
    console.error("AGGREGATION_SERVER_ERROR:", err);
    res.status(500).json({ error: "INTERNAL_SERVER_ERROR" });
  }
});

// 2. GEOPOLITICAL ROUTE
app.get('/api/mitre/geopolitical', async (req, res) => {
    try {
      const query = `
        SELECT 
          COALESCE(country, 'UNATTRIBUTED') AS country_name,
          json_agg(
            json_build_object(
              'name', name,
              'id', stix_id,           -- For frontend compatibility
              'stix_id', stix_id,      -- For database lookups
              'description', description
            )
          ) AS associated_groups
        FROM mitre_groups
        GROUP BY country
        ORDER BY country_name ASC;
      `;
      const result = await pool.query(query);
      res.json(result.rows);
    } catch (err) {
      console.error("GEO_SERVER_ERROR:", err);
      res.status(500).json({ error: "INTERNAL_SERVER_ERROR" });
    }
  });

// 3. ALL GROUPS ROUTE
app.get('/api/mitre/all-groups', async (req, res) => {
  try {
    const result = await pool.query('SELECT name, stix_id, description FROM mitre_groups ORDER BY name ASC;');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 4. TECHNIQUES ROUTE
app.get('/api/mitre/techniques', async (req, res) => {
    try {
      const result = await pool.query('SELECT technique_name, external_id, description FROM mitre_techniques ORDER BY technique_name ASC;');
      res.json(result.rows);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });
  
// 5. SOFTWARE/ARTIFACTS ROUTE
app.get('/api/mitre/software', async (req, res) => {
    const result = await pool.query('SELECT * FROM mitre_software ORDER BY name ASC');
    res.json(result.rows);
});

// 6. GROUP DETAILS ROUTE
app.get('/api/mitre/group-details/:id', async (req, res) => {
    const { id } = req.params;
    try {
      const groupRes = await pool.query('SELECT * FROM mitre_groups WHERE stix_id = $1', [id]);
      if (groupRes.rows.length === 0) return res.status(404).send('Not Found');
  
      const techRes = await pool.query(`
        SELECT t.t_code, t.name, t.description, t.tactic 
        FROM mitre_techniques t 
        JOIN mitre_relationships r ON t.stix_id = r.target_ref 
        WHERE r.source_ref = $1 AND r.relationship_type = 'uses'
      `, [id]);
  
      const softRes = await pool.query(`
        SELECT s.s_code, s.name, s.description, s.software_type 
        FROM mitre_software s 
        JOIN mitre_relationships r ON s.stix_id = r.target_ref 
        WHERE r.source_ref = $1 AND r.relationship_type = 'uses'
      `, [id]);
  
      console.log(`[ORCA_API] Dossier generated for ${id}: ${techRes.rowCount} techs, ${softRes.rowCount} software.`);
  
      res.json({
        ...groupRes.rows[0],
        associated_techniques: techRes.rows,
        associated_software: softRes.rows
      });
    } catch (err) {
      console.error('API_ERROR:', err);
      res.status(500).send('Internal Server Error');
    }
  });

// Start the Server
const PORT = 5000;
app.listen(PORT, () => {
  console.log(`--- ORCA_SERVER_ONLINE_ON_PORT_${PORT} ---`);
});
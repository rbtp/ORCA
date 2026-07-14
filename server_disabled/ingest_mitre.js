const axios = require('axios');
const { Pool } = require('pg');

const pool = new Pool({
  user: 'postgres',
  host: '127.0.0.1',
  database: 'orca_db',
  password: 'password',
  port: 5432,
});

const MITRE_STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json";

async function ingest() {
  try {
    console.log("FETCHING_MITRE_STIX_DATA...");
    const response = await axios.get(MITRE_STIX_URL);
    const groups = response.data.objects.filter(obj => obj.type === 'intrusion-set');

    const countries = ["China", "Russia", "Iran", "North Korea", "Vietnam", "Turkey", "South Korea"];

    for (const group of groups) {
      const stix_id = group.id;
      const name = group.name;
      const description = group.description || '';
      const aliases = JSON.stringify(group.aliases || []);
      const modified_at = group.modified;

      // Logic to determine country from description
      let foundCountry = null;
      countries.forEach(c => {
        if (description.toLowerCase().includes(c.toLowerCase())) foundCountry = c;
      });

      await pool.query(`
        INSERT INTO mitre_groups (stix_id, name, aliases, country, description, modified_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (stix_id) DO UPDATE 
        SET name = EXCLUDED.name, 
            country = EXCLUDED.country, 
            description = EXCLUDED.description,
            aliases = EXCLUDED.aliases,
            modified_at = EXCLUDED.modified_at;
      `, [stix_id, name, aliases, foundCountry, description, modified_at]);
    }

    console.log(`SUCCESS: INGESTED_${groups.length}_GROUPS`);
    process.exit();
  } catch (err) {
    console.error("INGESTION_FAILED:", err);
    process.exit(1);
  }
}

ingest();
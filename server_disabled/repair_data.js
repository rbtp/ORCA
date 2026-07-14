const fs = require('fs');
const { Pool } = require('pg');

const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'orca_db',
    password: 'password', // Add your DB password if you have one
    port: 5432,
});

async function repairSoftware() {
    console.log("--- STARTING DATABASE REPAIR ---");
    
    try {
        // Pointing to the correct folder: orcaweb\data\enterprise-attack.json
        const rawData = fs.readFileSync('../data/enterprise-attack.json'); 
        const mitreData = JSON.parse(rawData);

        const softwareObjects = mitreData.objects.filter(obj => 
            (obj.type === 'malware' || obj.type === 'tool') && !obj.revoked
        );

        console.log(`Found ${softwareObjects.length} software entries in JSON.`);

        for (const sw of softwareObjects) {
            const description = sw.description || "";
            const stix_id = sw.id;

            // Only update if we have a real description
            if (description && !description.includes("Telemetry indicates")) {
                await pool.query(
                    'UPDATE mitre_software SET description = $1 WHERE stix_id = $2',
                    [description, stix_id]
                );
            }
        }

        console.log("--- REPAIR COMPLETE ---");
    } catch (err) {
        console.error("Critical Error:", err.message);
    } finally {
        await pool.end();
        process.exit();
    }
}

repairSoftware();
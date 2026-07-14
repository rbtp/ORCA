const express = require('express');
const router = express.Router();
const db = require('../db'); // This points to your database connection file

router.get('/geopolitical', async (req, res) => {
    try {
        const query = `
            SELECT 
                c.name as country_name,
                json_agg(
                    json_build_object(
                        'id', g.external_id, 
                        'name', g.name
                    )
                ) as associated_groups
            FROM geopolitical_targets c
            JOIN attribution_map am ON c.id = am.country_id
            JOIN threat_groups g ON am.group_id = g.id
            GROUP BY c.name
            ORDER BY c.name ASC;
        `;
        
        const result = await db.query(query);
        res.json(result.rows); 
    } catch (err) {
        console.error("SQL_EXECUTION_ERROR:", err);
        res.status(500).json({ error: "Database connection failed" });
    }
});

module.exports = router;
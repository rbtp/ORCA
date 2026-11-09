--
-- PostgreSQL database dump
--

\restrict XJHjcdSvYD06CVPoQNwLNyjnfFiDe9yrYeSJbdrX6HCUaltlevTL0ACzD871EzJ

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
-- Data for Name: threat_attribution; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (1, 'APT-C-23', 'Palestine', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (2, 'APT-C-36', 'Colombia', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (3, 'Akira', 'Russia', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (4, 'BackdoorDiplomacy', 'China', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (5, 'BlackByte', 'Russia', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (6, 'BlackOasis', 'Middle East', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (7, 'LAPSUS$', 'Brazil/UK', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (8, 'Malteiro', 'Brazil', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (9, 'Poseidon Group', 'Brazil', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (10, 'Scattered Spider', 'USA/UK', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (11, 'FIN13', 'Mexico', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (12, 'Equation Group', 'USA', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (13, 'Blue Mockingbird', 'Russia', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (14, 'Carbanak', 'Russia', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (15, 'Cobalt Group', 'Russia', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (16, 'CostaRicto', 'Mercenary', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (17, 'Dark Caracal', 'Lebanon', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (18, 'DarkVishnya', 'Russia', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (19, 'DragonOK', 'China', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (20, 'Evilnum', 'Europe', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (21, 'FIN10', 'Russia', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (22, 'FIN4', 'USA', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (23, 'FIN8', 'Russia', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (24, 'Frankenstein', 'Pakistan', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (25, 'GCMAN', 'Russia', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (26, 'GOLD SOUTHFIELD', 'Russia', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (27, 'Gallmaker', 'Middle East', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (28, 'Gelsemium', 'China', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (29, 'INC Ransom', 'Russia', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (30, 'LazyScripter', 'Iran', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (31, 'Lotus Blossom', 'China', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (32, 'MONSOON', 'India', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (34, 'MoustachedBouncer', 'Belarus', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (35, 'NEODYMIUM', 'Middle East', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (36, 'PROMETHIUM', 'Turkey', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (37, 'Rancor', 'China', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (38, 'Sea Turtle', 'Turkey', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (39, 'SilverTerrier', 'Nigeria', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (40, 'Sowbug', 'China', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (41, 'Stealth Falcon', 'UAE', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (42, 'Storm-0501', 'Russia', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (43, 'Storm-1811', 'Russia', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (44, 'TA2541', 'Russia/CIS', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (45, 'TA505', 'Russia', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (46, 'TA551', 'Russia', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (47, 'TA578', 'Russia', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (48, 'Taidoor', 'China', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (49, 'TeamTNT', 'Germany', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (50, 'Threat Group-1314', 'China', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (51, 'Thrip', 'China', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (52, 'ToddyCat', 'China', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (53, 'Tropic Trooper', 'China', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (54, 'Velvet Ant', 'China', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (55, 'Volatile Cedar', 'Lebanon', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (56, 'WIRTE', 'Middle East', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (57, 'Whitefly', 'China', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (58, 'Windshift', 'Middle East', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (59, 'APT18', 'China', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (60, 'APT34', 'Iran', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (61, 'Confucius', 'India', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (62, 'DarkHydrus', 'Iran', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (63, 'Equation', 'USA', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (64, 'EXOTIC LILY', 'Russia', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (65, 'FIN6', 'Unknown', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (66, 'FIN7', 'Russia', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (67, 'HEXANE', 'Iran', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (68, 'Medusa Group', 'Russia', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (69, 'Molerats', 'Palestine', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (70, 'Mustard Tempest', 'Russia', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (71, 'Orangeworm', 'Unknown', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (72, 'PLATINUM', 'China', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (73, 'Play', 'Russia', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (74, 'Sharpshooter', 'North Korea', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (75, 'Stolen Pencil', 'North Korea', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (76, 'TA577', 'Unknown', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (77, 'Windigo', 'Russia', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (78, 'Wizard Spider', 'Russia', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (79, 'Dragonfly', 'Russia', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (80, 'OilRig', 'Iran', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (81, 'Fox Kitten', 'Iran', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (82, 'Lazarus Group', 'North Korea', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (83, 'Leafminer', 'Middle East', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (84, 'APT42', 'Iran', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (85, 'Earth Lusca', 'China', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (86, 'Magic Hound', 'Iran', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (87, 'APT17', 'China', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (88, 'Sandworm Team', 'Russia', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (89, 'UNC2452', 'Russia', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (90, 'Turla', 'Russia', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (91, 'Ember Bear', 'Russia', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (92, 'Patchwork', 'India', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (93, 'APT28', 'Russia', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (94, 'Ke3chang', 'China', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (95, 'Volt Typhoon', 'China', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (96, 'APT29', 'Russia', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (97, 'Andariel', 'North Korea', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (98, 'HAFNIUM', 'China', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (99, 'APT39', 'Iran', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (100, 'MuddyWater', 'Iran', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (101, 'APT38', 'North Korea', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (102, 'APT32', 'Vietnam', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (103, 'Kimsuky', 'North Korea', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (104, 'Leviathan', 'China', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (105, 'Mustang Panda', 'China', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (106, 'menuPass', 'China', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (107, 'Operation Wocao', 'China', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (108, 'APT19', 'China', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (109, 'APT37', 'North Korea', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (110, 'APT41', 'China', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (111, 'Winnti Group', 'China', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (112, 'Saint Bear', 'Russia', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (113, 'Dragonfly 2.0', 'Russia', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (114, 'Sidewinder', 'India', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (115, 'APT30', 'China', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (116, 'Threat Group-3390', 'China', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (117, 'Gamaredon Group', 'Russia', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (118, 'Agrius', 'Iran', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (119, 'Moonstone Sleet', 'North Korea', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (120, 'Axiom', 'China', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (121, 'APT12', 'China', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (122, 'APT3', 'China', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (123, 'APT1', 'China', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (124, 'Naikon', 'China', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (125, 'Machete', 'Venezuela', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (126, 'SideCopy', 'Pakistan', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (127, 'APT33', 'Iran', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (128, 'AppleJeus', 'North Korea', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (129, 'Charming Kitten', 'Iran', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (130, 'Chimera', 'China', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (131, 'Aquatic Panda', 'China', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (132, 'UNC3886', 'China', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (133, 'BRONZE BUTLER', 'China', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (134, 'GALLIUM', 'China', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (135, 'APT5', 'China', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (136, 'ZIRCONIUM', 'China', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (137, 'Tonto Team', 'China', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (138, 'BlackTech', 'China', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (139, 'Deep Panda', 'China', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (140, 'Putter Panda', 'China', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (141, 'Aoqin Dragon', 'China', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (142, 'admin@338', 'China', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (143, 'Moafee', 'China', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (144, 'Contagious Interview', 'North Korea', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (145, 'Suckfly', 'North Korea', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (146, 'Higaisa', 'North Korea', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (147, 'RedCurl', 'Russia', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (148, 'Indrik Spider', 'Russia', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (149, 'Silence', 'Russia', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (150, 'Winter Vivern', 'Russia/Belarus', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (151, 'Star Blizzard', 'Russia', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (152, 'Cinnamon Tempest', 'Russia', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (153, 'FIN5', 'Russia', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (154, 'CURIUM', 'Iran', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (155, 'Moses Staff', 'Iran', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (156, 'POLONIUM', 'Lebanon/Iran', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (157, 'BITTER', 'South Asia', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (158, 'Transparent Tribe', 'Pakistan', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (159, 'Gorgon Group', 'Pakistan', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (160, 'Nomadic Octopus', 'Central Asia', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (161, 'LuminousMoth', 'China', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (162, 'Rocke', 'China', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (163, 'Daggerfly', 'China', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (33, 'Metador', 'Mercenary', true);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (165, 'Inception', 'Unknown/Multi-state', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (166, 'Salt Typhoon', 'China', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (167, 'Darkhotel', 'South Korea', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (168, 'Silent Librarian', 'Iran', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (169, 'Elderwood', 'China', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (170, 'CopyKittens', 'Iran', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (171, 'IndigoZebra', 'China', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (172, 'RTM', 'Russia', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (173, 'The White Company', 'Unknown', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (174, 'Ajax Security Team', 'Iran', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (175, 'Ferocious Kitten', 'Iran', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (176, 'Mofang', 'China', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (177, 'TA459', 'China', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (178, 'Cleaver', 'Iran', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (179, 'RedEcho', 'China', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (180, 'Group5', 'Iran', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (181, 'Water Galura', 'China', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (182, 'Strider', 'USA', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (183, 'PittyTiger', 'China', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (184, 'APT16', 'China', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (185, 'Scarlet Mimic', 'China', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (186, 'Honeybee', 'North Korea', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (187, 'Night Dragon', 'China', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (188, 'TEMP.Veles', 'Russia', NULL);
INSERT INTO public.threat_attribution (id, group_name, attribution, is_static) VALUES (189, 'Dust Storm', 'China', NULL);


--
-- Name: threat_attribution_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.threat_attribution_id_seq', 189, true);


--
-- PostgreSQL database dump complete
--

\unrestrict XJHjcdSvYD06CVPoQNwLNyjnfFiDe9yrYeSJbdrX6HCUaltlevTL0ACzD871EzJ


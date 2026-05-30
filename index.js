// beware this is TERRIBLY vibecoded cuz i dont wanna deal with vpn api bullshit cuz im lazy and dumb

const { Client, GatewayIntentBits, EmbedBuilder, ActionRowBuilder, ButtonBuilder, ButtonStyle, PermissionFlagsBits, ActivityType } = require('discord.js');
const express = require('express');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
require('dotenv').config();

const config = {
    token:      process.env.DISCORD_TOKEN,
    clientId:   process.env.CLIENT_ID,
    port:       parseInt(process.env.PORT) || 4253,
    vpnApiKey:  process.env.VPN_API_KEY,
    prefix:     process.env.PREFIX || 'v!',
    ipHashSalt: process.env.IP_HASH_SALT
};

// ─── IP Hashing ───────────────────────────────────────────────────────────────
// IPs are never stored in plaintext. We use a salted SHA-256 hash so that:
//   1. The same IP always produces the same hash (for alt detection)
//   2. The hash cannot be reversed to recover the original IP
function hashIP(ip) {
    return crypto
        .createHmac('sha256', config.ipHashSalt)
        .update(ip.trim().toLowerCase())
        .digest('hex');
}
// ──────────────────────────────────────────────────────────────────────────────

// ─── Persistent storage files ─────────────────────────────────────────────────
const CONFIG_FILE   = './guild-configs.json';
const IP_MAP_FILE   = './ip-map.json';      // { ipHash: [userId, userId, ...] }
const USER_IP_FILE  = './user-ip.json';     // { userId: ipHash }

let guildConfigs = {};
let ipMap        = {};   // ipHash → Set of userIds (serialized as array)
let userIPMap    = {};   // userId → ipHash
// ──────────────────────────────────────────────────────────────────────────────

// ─── In-memory cooldown map (fix #1) ─────────────────────────────────────────
// Prevents duplicate /verify requests within a 10-second window per user.
const verifyInProgress = new Map(); // userId → timestamp
// ──────────────────────────────────────────────────────────────────────────────

// ─── Load / save helpers ──────────────────────────────────────────────────────
function loadJSON(file, fallback = {}) {
    try {
        if (fs.existsSync(file)) return JSON.parse(fs.readFileSync(file, 'utf8'));
    } catch (e) {
        console.error(`Error loading ${file}:`, e.message);
    }
    return fallback;
}

function saveJSON(file, data) {
    try {
        fs.writeFileSync(file, JSON.stringify(data, null, 2));
    } catch (e) {
        console.error(`Error saving ${file}:`, e.message);
    }
}

function loadAll() {
    guildConfigs = loadJSON(CONFIG_FILE);
    userIPMap    = loadJSON(USER_IP_FILE);

    // ip-map values are stored as plain arrays; convert to Sets internally
    const rawIPMap = loadJSON(IP_MAP_FILE);
    for (const [hash, ids] of Object.entries(rawIPMap)) {
        ipMap[hash] = new Set(ids);
    }
    console.log(`Loaded configs for ${Object.keys(guildConfigs).length} guilds`);
    console.log(`Loaded ${Object.keys(ipMap).length} unique IP records (hashed)`);
}

function saveIPData() {
    // Convert Sets back to arrays for JSON serialization
    const serializable = {};
    for (const [hash, ids] of Object.entries(ipMap)) {
        serializable[hash] = [...ids];
    }
    saveJSON(IP_MAP_FILE, serializable);
    saveJSON(USER_IP_FILE, userIPMap);
}
// ──────────────────────────────────────────────────────────────────────────────

// ─── Guild config helpers ─────────────────────────────────────────────────────
function getGuildConfig(guildId) {
    if (!guildConfigs[guildId]) {
        guildConfigs[guildId] = { verifiedRoleId: null, logChannelId: null };
        saveJSON(CONFIG_FILE, guildConfigs);
    }
    return guildConfigs[guildId];
}

function setGuildConfig(guildId, key, value) {
    if (!guildConfigs[guildId]) guildConfigs[guildId] = {};
    guildConfigs[guildId][key] = value;
    saveJSON(CONFIG_FILE, guildConfigs);
}
// ──────────────────────────────────────────────────────────────────────────────

// ─── Alt detection core ───────────────────────────────────────────────────────
/**
 * Records an IP hash → userId association and returns any existing accounts
 * that share the same IP hash (i.e. potential alts).
 *
 * @param {string} userId
 * @param {string} ipHash
 * @returns {string[]} array of OTHER userIds that share this IP hash
 */
function recordAndCheckAlts(userId, ipHash) {
    const existing = ipMap[ipHash] ? [...ipMap[ipHash]] : [];
    const alts = existing.filter(id => id !== userId);

    // Update maps
    if (!ipMap[ipHash]) ipMap[ipHash] = new Set();
    ipMap[ipHash].add(userId);
    userIPMap[userId] = ipHash;

    saveIPData();
    return alts;
}
// ──────────────────────────────────────────────────────────────────────────────

// ─── HTML page builder ────────────────────────────────────────────────────────
function buildPage({ title, body }) {
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <link rel="icon" href="https://korona.lat/images/nreds.png" type="image/png">
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Quicksand:wght@300..700&display=swap" rel="stylesheet">
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Quicksand', sans-serif;
      background: #000;
      color: #e0d0ff;
      min-height: 100vh;
      display: flex;
      justify-content: center;
      align-items: center;
      overflow: hidden;
    }
    #vanta-bg { position: fixed; inset: 0; z-index: 0; }
    .container {
      position: relative; z-index: 1;
      display: flex; justify-content: center; align-items: center;
      min-height: 100vh; padding: 20px;
    }
    .box {
      background: rgba(8, 0, 18, 0.82);
      border: 1px solid rgba(120, 0, 255, 0.45);
      border-radius: 12px; padding: 36px 32px;
      text-align: center; max-width: 420px; width: 100%;
      box-shadow: 0 0 0 1px rgba(120,0,255,0.08), 0 0 30px rgba(120,0,255,0.33), 0 0 80px rgba(120,0,255,0.13);
      backdrop-filter: blur(12px);
      animation: fadeUp 0.5s ease both;
    }
    @keyframes fadeUp {
      from { opacity: 0; transform: translateY(18px); }
      to   { opacity: 1; transform: translateY(0); }
    }
    .box h2 {
      font-size: 1.35rem; font-weight: 700; color: #bf80ff;
      letter-spacing: 0.08em; text-transform: lowercase;
      margin-bottom: 14px; text-shadow: 0 0 16px #7800ff;
    }
    .box p { font-size: 0.82rem; line-height: 1.7; color: #b49fd4; }
    .box code {
      background: rgba(120,0,255,0.18); border: 1px solid rgba(120,0,255,0.3);
      border-radius: 4px; padding: 1px 6px; font-size: 0.8rem; color: #d4aaff;
    }
    .divider {
      height: 1px;
      background: linear-gradient(to right, transparent, rgba(120,0,255,0.45), transparent);
      margin: 18px 0;
    }
  </style>
</head>
<body>
  <div id="vanta-bg"></div>
  <div class="container">
    <div class="box">
      <h2>${title}</h2>
      <div class="divider"></div>
      ${body}
    </div>
  </div>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r121/three.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/vanta@latest/dist/vanta.fog.min.js"></script>
  <script>
    VANTA.FOG({
      el: "#vanta-bg", mouseControls: true, touchControls: true, gyroControls: false,
      minHeight: 200.00, minWidth: 200.00,
      highlightColor: 0x0, midtoneColor: 0x7800ff, lowlightColor: 0x8600ff, baseColor: 0x0
    });
  </script>
</body>
</html>`;
}
// ──────────────────────────────────────────────────────────────────────────────

const client = new Client({
    intents: [
        GatewayIntentBits.Guilds,
        GatewayIntentBits.GuildMembers,
        GatewayIntentBits.GuildMessages,
        GatewayIntentBits.MessageContent
    ]
});

const app = express();
app.set('trust proxy', true);
app.use(express.static('public'));

const processedMessages = new Set();

// Check if IP is using VPN
async function checkVPN(ip) {
    try {
        const response = await axios.get(`https://vpnapi.io/api/${ip}`, {
            params: { key: config.vpnApiKey }
        });
        return {
            isVPN: response.data.security.vpn || response.data.security.proxy || response.data.security.tor,
            details: response.data
        };
    } catch (error) {
        console.error('VPN check error:', error.message);
        return { isVPN: false, details: null };
    }
}

// ─── Alt action: ban alt, DM main account ────────────────────────────────────
async function handleAltDetected({ guild, altMember, mainUserId, logChannel }) {
    const altUser = altMember.user;

    // 1. DM the main account
    try {
        const mainUser = await client.users.fetch(mainUserId);
        await mainUser.send(
            `**hi there, so we detected an alt account on ${guild.name}**\n\n` +
            `this account (**${altUser.tag}**) tried to verify, but you were in the same network.\n` +
            `this alt has been automatically banned for safety.\n\n` +
            `if this wasn't you, please contact a server admin, sorry!\n` +
            `you can also contact @aubreelat. for help.`
        );
    } catch (e) {
        console.warn(`Could not DM main user ${mainUserId}:`, e.message);
    }

    // 2. Ban the alt
    try {
        await altMember.ban({
            reason: `alt account detected — shares ip hash with user ${mainUserId}`
        });
        console.log(`banned alt ${altUser.tag} (${altUser.id}) in guild ${guild.id}`);
    } catch (e) {
        console.error(`failed to ban alt ${altUser.tag}:`, e.message);
    }

    // 3. Log it
    if (logChannel) {
        const embed = new EmbedBuilder()
            .setColor('#ff4400')
            .setTitle('alt account detected & banned, hah loser.')
            .setThumbnail(altUser.displayAvatarURL())
            .addFields(
                { name: 'Alt Account', value: `${altUser.tag} (${altUser.id})`, inline: true },
                { name: 'Linked Main', value: `<@${mainUserId}> (${mainUserId})`, inline: true },
                { name: 'Action', value: 'Alt banned · Main account warned via DM', inline: false }
            )
            .setTimestamp();
        await logChannel.send({ embeds: [embed] });
    }
}
// ──────────────────────────────────────────────────────────────────────────────

// Express route for verification
app.get('/verify/:userId/:guildId', async (req, res) => {
    const { userId, guildId } = req.params;

    // ── Fix #1: Block Discord's link unfurler / preview fetcher ───────────
    // Discord sends multiple HEAD/GET requests when a URL appears in a message.
    // These requests don't always carry the 'Discordbot' UA, so we widen the check.
    const userAgent = req.headers['user-agent'] || '';
    if (
        !userAgent ||
        userAgent.toLowerCase().includes('discord') ||
        userAgent.toLowerCase().includes('bot') ||
        userAgent.toLowerCase().includes('preview') ||
        userAgent.toLowerCase().includes('crawler') ||
        userAgent.toLowerCase().includes('spider') ||
        req.method === 'HEAD'
    ) {
        return res.send('ok');
    }
    // ─────────────────────────────────────────────────────────────────────

    // ── Fix #2: Per-user cooldown to prevent duplicate concurrent requests ─
    const lastAttempt = verifyInProgress.get(userId);
    if (lastAttempt && Date.now() - lastAttempt < 10_000) {
        return res.send(buildPage({
            title: 'hold on :3',
            body: `<p>you already have a verification in progress.<br>please wait a few seconds and try again.</p>`
        }));
    }
    verifyInProgress.set(userId, Date.now());
    setTimeout(() => verifyInProgress.delete(userId), 10_000);
    // ─────────────────────────────────────────────────────────────────────

    let userIP = req.ip ||
                 req.headers['x-forwarded-for'] ||
                 req.headers['x-real-ip'] ||
                 req.socket.remoteAddress;

    if (userIP && userIP.includes(',')) userIP = userIP.split(',')[0].trim();
    if (userIP && userIP.includes(':') && !userIP.includes('::')) {
        const parts = userIP.split(':');
        if (parts.length === 2 && !isNaN(parts[1])) userIP = parts[0];
    }

    const cleanIP = userIP.replace('::ffff:', '').trim();

    if (cleanIP === '::1' || cleanIP === '127.0.0.1') {
        return res.send(buildPage({
            title: 'browser not supported',
            body: `<p>your browser is blocking vpn checking.<br>please open this link in <strong>Chrome</strong>, <strong>Edge</strong>, or <strong>Safari</strong> instead.</p>`
        }));
    }

    console.log(`Verification attempt — User: ${userId}, Guild: ${guildId}, IP: [hashed]`);

    try {
        const guild = await client.guilds.fetch(guildId);
        const guildConfig = getGuildConfig(guildId);

        if (!guildConfig.verifiedRoleId) {
            return res.send(buildPage({
                title: 'server not configured',
                body: `<p>this server hasn't been set up for verification yet.<br>ask an administrator to run <code>v!setup</code>.</p>`
            }));
        }

        // VPN check first
        const vpnCheck = await checkVPN(cleanIP);
        const member = await guild.members.fetch(userId);
        const logChannel = guildConfig.logChannelId
            ? guild.channels.cache.get(guildConfig.logChannelId)
            : null;

        if (vpnCheck.isVPN) {
            if (logChannel) {
                const logEmbed = new EmbedBuilder()
                    .setColor('#ed4245')
                    .setTitle('Verification Failed - VPN Detected')
                    .setThumbnail(member.user.displayAvatarURL())
                    .addFields(
                        { name: 'User', value: `${member.user.tag} (${member.id})`, inline: true },
                        { name: 'Security', value: 'VPN/Proxy/Tor Detected', inline: false }
                    )
                    .setTimestamp();
                await logChannel.send({ embeds: [logEmbed] });
            }
            return res.send(buildPage({
                title: 'verification failed',
                body: `<p>vpn / proxy detected.<br>please disable your VPN and try again.</p>`
            }));
        }

        // ── Alt detection ──────────────────────────────────────────────────
        const ipHash = hashIP(cleanIP);
        const altUserIds = recordAndCheckAlts(userId, ipHash);

        if (altUserIds.length > 0) {
            console.log(`Alt detected: ${userId} shares IP hash with [${altUserIds.join(', ')}] in guild ${guildId}`);

            // The *new* account is the alt — ban it and warn the pre-existing ones
            for (const mainUserId of altUserIds) {
                try {
                    await handleAltDetected({ guild, altMember: member, mainUserId, logChannel });
                } catch (e) {
                    console.error('Alt handling error:', e.message);
                }
            }

            return res.send(buildPage({
                title: 'alt account detected',
                body: `<p>this account has been flagged as an alt.<br>you have been banned and the original account has been notified.<br><br>if this is a mistake, contact a server admin.</p>`
            }));
        }
        // ──────────────────────────────────────────────────────────────────

        // All good — assign verified role
        const role = guild.roles.cache.get(guildConfig.verifiedRoleId);
        if (role) await member.roles.add(role);

        if (logChannel) {
            const logEmbed = new EmbedBuilder()
                .setColor('#3ba55d')
                .setTitle('Verification Successful')
                .setThumbnail(member.user.displayAvatarURL())
                .addFields(
                    { name: 'User', value: `${member.user.tag} (${member.id})`, inline: true },
                    { name: 'Security', value: 'Clean — No VPN, No Alt', inline: false },
                    { name: 'Tuff?', value: 'Very Tuff :33', inline: true }
                )
                .setTimestamp();
            await logChannel.send({ embeds: [logEmbed] });
        }

        res.send(buildPage({
            title: 'verified',
            body: `<p>holy tuff you are verified :33</p>`
        }));

        console.log(`User ${userId} verified successfully in guild ${guildId}`);

    } catch (error) {
        console.error('Verification error:', error);
        res.send(buildPage({
            title: 'error',
            body: `<p>an error occurred during verification.<br>please try again or contact an administrator.</p>`
        }));
    }
});

client.once('ready', () => {
    console.log(`Bot logged in as ${client.user.tag}`);
    console.log(`Verification server running on port ${config.port}`);
    console.log(`Bot is in ${client.guilds.cache.size} servers`);
    loadAll();

    const statuses = [
        { name: 'korona.lat on top', type: ActivityType.Watching },
        { name: `${client.guilds.cache.size} servers`, type: ActivityType.Watching },
        { name: 'Lets take a look... 👀', type: ActivityType.Watching },
        { name: 'Furry Aim Trainer', type: ActivityType.Playing },
        { name: '#observing for blocked links...👀👀👀', type: ActivityType.Playing },
        { name: 'aubree is mommy', type: ActivityType.Competing },
    ];

    let i = 0;
    const setStatus = () => {
        const s = statuses[i % statuses.length];
        client.user.setPresence({ activities: [{ name: s.name, type: s.type }], status: 'dnd' });
        i++;
    };
    setTimeout(() => { setStatus(); setInterval(setStatus, 15_000); }, 5000);
});

// Handle button interactions
client.on('interactionCreate', async (interaction) => {
    if (!interaction.isButton()) return;
    if (interaction.customId === 'verify_button') {
        const guildConfig = getGuildConfig(interaction.guild.id);

        // ── Fix #3: Don't re-issue a link if user is already verified ─────
        if (guildConfig.verifiedRoleId && interaction.member.roles.cache.has(guildConfig.verifiedRoleId)) {
            return interaction.reply({ content: `you're already verified :33`, ephemeral: true });
        }
        // ─────────────────────────────────────────────────────────────────

        const verifyUrl = `https://verify.korona.lat/verify/${interaction.user.id}/${interaction.guild.id}`;
        await interaction.reply({ content: `Click here to verify: ${verifyUrl}`, ephemeral: true });
    }
});

// Prefix commands
client.on('messageCreate', async (message) => {
    if (message.author.bot || !message.content.startsWith(config.prefix)) return;
    if (processedMessages.has(message.id)) return;
    processedMessages.add(message.id);
    setTimeout(() => processedMessages.delete(message.id), 5000);

    const args = message.content.slice(config.prefix.length).trim().split(/ +/);
    const command = args.shift().toLowerCase();

    // ── setup ──────────────────────────────────────────────────────────────
    if (command === 'setup') {
        if (!message.member.permissions.has(PermissionFlagsBits.Administrator))
            return message.reply('You need Administrator permission to use this command.');

        const guildConfig = getGuildConfig(message.guild.id);
        const embed = new EmbedBuilder()
            .setColor('#7800ff')
            .setTitle('Verification Bot Setup')
            .setDescription('Current configuration for this server:')
            .addFields(
                { name: 'Verified Role', value: guildConfig.verifiedRoleId ? `<@&${guildConfig.verifiedRoleId}>` : 'Not set', inline: true },
                { name: 'Log Channel', value: guildConfig.logChannelId ? `<#${guildConfig.logChannelId}>` : 'Not set', inline: true },
                { name: 'Setup Commands', value: '`v!setrole @role` — Set the verified role\n`v!setlog #channel` — Set the log channel', inline: false }
            );
        await message.reply({ embeds: [embed] });
    }

    // ── setrole ────────────────────────────────────────────────────────────
    if (command === 'setrole') {
        if (!message.member.permissions.has(PermissionFlagsBits.Administrator))
            return message.reply('You need Administrator permission to use this command.');
        const role = message.mentions.roles.first();
        if (!role) return message.reply('Please mention a role. Example: `v!setrole @Verified`');
        setGuildConfig(message.guild.id, 'verifiedRoleId', role.id);
        await message.reply(`✅ Verified role set to ${role}`);
    }

    // ── setlog ─────────────────────────────────────────────────────────────
    if (command === 'setlog') {
        if (!message.member.permissions.has(PermissionFlagsBits.Administrator))
            return message.reply('You need Administrator permission to use this command.');
        const channel = message.mentions.channels.first();
        if (!channel) return message.reply('Please mention a channel. Example: `v!setlog #verification-logs`');
        setGuildConfig(message.guild.id, 'logChannelId', channel.id);
        await message.reply(`✅ Log channel set to ${channel}`);
    }

    // ── manualverify ───────────────────────────────────────────────────────
    if (command === 'manualverify') {
        if (!message.member.permissions.has(PermissionFlagsBits.ManageRoles))
            return message.reply('You do not have permission to use this command.');

        const guildConfig = getGuildConfig(message.guild.id);
        if (!guildConfig.verifiedRoleId)
            return message.reply('Please set up the verified role first using `v!setrole @role`');

        const targetUser = message.mentions.users.first();
        if (!targetUser) return message.reply('Please mention a user to verify.');

        const member = message.guild.members.cache.get(targetUser.id);
        if (!member) return message.reply('User not found in this server.');

        try {
            const role = message.guild.roles.cache.get(guildConfig.verifiedRoleId);
            if (role) {
                await member.roles.add(role);
                const logChannel = guildConfig.logChannelId
                    ? message.guild.channels.cache.get(guildConfig.logChannelId)
                    : null;
                if (logChannel) {
                    const logEmbed = new EmbedBuilder()
                        .setColor('#7800ff')
                        .setTitle('Manual Verification')
                        .setThumbnail(member.user.displayAvatarURL())
                        .addFields(
                            { name: 'User', value: `${member.user.tag} (${member.id})`, inline: true },
                            { name: 'Verified By', value: `${message.author.tag} (${message.author.id})`, inline: true },
                            { name: 'Method', value: 'Manual verification by staff', inline: false }
                        )
                        .setTimestamp();
                    await logChannel.send({ embeds: [logEmbed] });
                }
                await message.reply(`✅ Successfully verified ${targetUser.tag}`);
            } else {
                await message.reply('Verified role not found. Please check configuration.');
            }
        } catch (error) {
            console.error('Manual verification error:', error);
            await message.reply('An error occurred while verifying the user.');
        }
    }

    // ── altcheck ───────────────────────────────────────────────────────────
    if (command === 'altcheck') {
        if (!message.member.permissions.has(PermissionFlagsBits.Administrator))
            return message.reply('You need Administrator permission to use this command.');

        const targetUser = message.mentions.users.first();
        if (!targetUser) return message.reply('Please mention a user. Example: `v!altcheck @user`');

        const ipHash = userIPMap[targetUser.id];
        if (!ipHash) {
            return message.reply(`No verification record found for **${targetUser.tag}**. They may not have verified yet.`);
        }

        const linkedIds = [...(ipMap[ipHash] || [])].filter(id => id !== targetUser.id);
        if (linkedIds.length === 0) {
            return message.reply(`✅ **${targetUser.tag}** has no known alt accounts.`);
        }

        const mentions = linkedIds.map(id => `<@${id}> (${id})`).join('\n');
        const embed = new EmbedBuilder()
            .setColor('#ff4400')
            .setTitle(`Alt Report — ${targetUser.tag}`)
            .setDescription(`The following accounts share the same IP hash:`)
            .addFields({ name: 'Linked Accounts', value: mentions })
            .setFooter({ text: 'IP data is stored as a one-way hash — originals are never kept.' })
            .setTimestamp();
        await message.reply({ embeds: [embed] });
    }

    // ── altunlink ──────────────────────────────────────────────────────────
    if (command === 'altunlink') {
        if (!message.member.permissions.has(PermissionFlagsBits.Administrator))
            return message.reply('You need Administrator permission to use this command.');

        const targetUser = message.mentions.users.first();
        if (!targetUser) return message.reply('Please mention a user. Example: `v!altunlink @user`');

        const ipHash = userIPMap[targetUser.id];
        if (!ipHash) {
            return message.reply(`No IP record found for **${targetUser.tag}**.`);
        }

        if (ipMap[ipHash]) {
            ipMap[ipHash].delete(targetUser.id);
            if (ipMap[ipHash].size === 0) delete ipMap[ipHash];
        }
        delete userIPMap[targetUser.id];
        saveIPData();

        await message.reply(`✅ Cleared IP record for **${targetUser.tag}**. They can re-verify fresh.`);
    }

    // ── verify panel ───────────────────────────────────────────────────────
    if (command === 'verify') {
        if (!message.member.permissions.has(PermissionFlagsBits.ManageGuild))
            return message.reply('You do not have permission to use this command.');

        const guildConfig = getGuildConfig(message.guild.id);
        if (!guildConfig.verifiedRoleId)
            return message.reply('Please set up the verified role first using `v!setrole @role`');

        const embed = new EmbedBuilder()
            .setColor('#7800ff')
            .setTitle('verification!!!!!!!!!!!')
            .setDescription('to avoid bots, please verify yourself by clicking the button below\n\ndo note: vpn\'s and proxies are not allowed >:c')
            .setFooter({ text: 'This link is safe, i dont log ips as clearly shown in the screenshot below. only VPNapi does (external provider), this is to avoid bots. if ur uncomfortable clicking the link. dm an admin' });

        const row = new ActionRowBuilder().addComponents(
            new ButtonBuilder()
                .setCustomId('verify_button')
                .setLabel('verify now >:3')
                .setStyle(ButtonStyle.Primary)
        );

        await message.channel.send({ embeds: [embed], components: [row] });
        await message.delete().catch(() => {});
    }
});

app.listen(config.port, () => {
    console.log(`Verification server started on port ${config.port}`);
});

client.login(config.token);

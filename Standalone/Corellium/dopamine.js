const { Corellium } = require("@corellium/corellium-api");
const config = require("./endpoint.json");
const https = require("https");
const fs = require("fs");
const os = require("os");
const path = require("path");

const BOOTSTRAP_URL =
    "https://apt.procurs.us/bootstraps/1900/bootstrap-ssh-iphoneos-arm64.tar.zst";

function downloadToFile(url, destPath) {
    return new Promise((resolve, reject) => {
        const file = fs.createWriteStream(destPath);

        const request = https.get(url, (response) => {
            if (
                response.statusCode >= 300 &&
                response.statusCode < 400 &&
                response.headers.location
            ) {
                response.resume();
                file.close();
                const redirectUrl = new URL(
                    response.headers.location,
                    url,
                ).toString();
                downloadToFile(redirectUrl, destPath).then(resolve, reject);
                return;
            }

            if (response.statusCode !== 200) {
                response.resume();
                file.close();
                fs.unlink(destPath, () => {});
                reject(
                    new Error(
                        `Failed to download ${url}: HTTP ${response.statusCode}`,
                    ),
                );
                return;
            }

            response.pipe(file);
            file.on("finish", () => file.close(() => resolve(destPath)));
        });

        request.on("error", (err) => {
            file.close();
            fs.unlink(destPath, () => {});
            reject(err);
        });
    });
}

async function main() {
    // Parse command line arguments.
    let mode = process.argv[2];
    let projectArg = process.argv[3];
    let instanceArg = process.argv[4];

    if ((mode !== "install" && mode !== "activate") || !projectArg || !instanceArg) {
        console.error("Usage: node install.js <install|activate> <project-name-or-id> <instance-name-or-id>");
        process.exit(1);
    }

    // Configure the API.
    let corellium = new Corellium({
        endpoint: config.endpoint,
        username: config.username,
        password: config.password,
    });

    console.log("Logging in...");
    // Login.
    await corellium.login();

    // Get the list of projects.
    let projects = await corellium.projects();

    // Find the project by name or id.
    let project = projects.find(
        (project) => project.name === projectArg || project.id === projectArg,
    );

    if (!project) {
        console.error(`Project not found: ${projectArg}`);
        process.exit(1);
    }

    // Get the instances in the project.
    console.log("Getting instances...");
    let instances = await project.instances();

    // Find the instance by name or id.
    let instance = instances.find(
        (instance) => instance.name === instanceArg || instance.id === instanceArg,
    );

    if (!instance) {
        console.error(`Instance not found: ${instanceArg}`);
        process.exit(1);
    }

    console.log("Got instance");
    await instance.waitForAgentReady();
    let agent = await instance.agent();
    console.log("Got agent");

    await agent.ready();
    console.log("Agent ready");

    if (mode === "install") {
        try { await agent.deleteFile("/private/preboot/dopamine") } catch(e) {}
        try { await agent.deleteFile("/private/preboot/Dopamine.tar") } catch(e) {}
        try { await agent.deleteFile("/private/preboot/bootstrap_1900.tar.zst") } catch(e) {}

        // Download the bootstrap to a temp file (only needed to install).
        let bootstrapPath;
        if (mode === "install") {
            bootstrapPath = path.join(os.tmpdir(), "bootstrap_1900.tar.zst");
            console.log(`Downloading bootstrap to ${bootstrapPath}...`);
            await downloadToFile(BOOTSTRAP_URL, bootstrapPath);
            console.log("Bootstrap downloaded");
        }

        console.log("Uploading bootstrap to device...");
        await agent.upload("/private/preboot/bootstrap_1900.tar.zst", fs.createReadStream(bootstrapPath));
        console.log("Uploading Dopamine tarball to device...");
        await agent.upload("/private/preboot/Dopamine.tar", fs.createReadStream('../Dopamine.tar'));
        console.log("Uploading Dopamine binary to device...");
        await agent.upload("/private/preboot/dopamine", fs.createReadStream('../../BaseBin/dopamine/dopamine'));
        await agent.changeFileAttributes("/private/preboot/dopamine", {mode: 775}); 
    }

    let command =
        mode === "install"
            ? "/private/preboot/dopamine install /private/preboot/Dopamine.tar /private/preboot/bootstrap_1900.tar.zst"
            : "/var/jb/basebin/dopamine activate";
    console.log("Executing dopamine...")
    result = await agent.shellExec(command);

    if (!result.success) {
        console.log("Failed to run binary, ensure BaseBin/dopamine/dopamine binaries CDHash has been added to trustcache in the corellium instance under Settings -> Trust Cache")
    }
    else {
        console.log(`Dopamine returned ${result["exit-status"]}`)
        for (const line of result.output.split("\n")) {
            console.log(line);
        }
    }

    agent.disconnect();

    return;
}

main().catch((err) => {
    console.error(err);
});

# Your Podcast Site

This is a template repository for creating a podcast site with [podbard](https://github.com/Songmu/podbard). After setting up a repository from this template, please do the following

## What to do next

1. Congiguration
    - Adjust the `podbard.yam` file to fit your podcast site
    - Locate `static/images/artwwork.jpg` if you like
2. Locate the audio files (MP3 or M4A) and commit them
    - Put the audio files in the `audio/` directory (You should remove the sample files)
3. Locate the episode files (Markdown) and commit them
    - Put the episode files in the `episode/` directory (You should remove the sample files)
    - Hint: You can use the `podbard episode <your.mp3>` subcommand to create a new episode file
4. Push, build and deploy to the Cloudflare Pages and R2
    - After the push, the GitHub Actions will build the site and deploy it to the Cloudflare Pages and R2
    - Check [.github/workflows/](./.github/workflows/) for specific settings

## Setting for Cloudflare Pages and R2

This template is designed to upload page content to Cloudflare Pages and audio files to Cloudflare R2. Look at the GitHub Actions workflow files under the .github directory and set the necessary values.

## Basic Authentication Settings

This template uses Basic Authentication for private podcasting. The Basic Authentication user and password can be set by entering a value such as `PASSWORD_FOO` in the Cloudflare Pages environment variable. In this case, the password for the foo user will be the value you set. You can subscribe to the podcast at the feed URL such as `https://foo:password@yourpodcast.example.com/feed.xml`. Check [`functions/_middleware.ts`](./functions/_middleware.ts) for implementation details.

Note: This basic authentication is not perfect for privatization. It can be directly retrieved if the audio file URL is compromised. However, we believe this method is relatively reasonable.

## Customization

You can manage the podcast site with the `podbard` command for more customization.

See. <https://github.com/Songmu/podbard> for more details.

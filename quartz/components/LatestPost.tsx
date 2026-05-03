import { QuartzComponent, QuartzComponentConstructor, QuartzComponentProps } from "./types"
import { resolveRelative } from "../util/path"

export default (() => {
  const LatestPost: QuartzComponent = ({ allFiles, fileData }: QuartzComponentProps) => {
    // Filter out the homepage and files without dates, then sort descending
    const posts = allFiles
      .filter((f) => f.slug !== "index" && f.dates?.published)
      .sort((a, b) => (b.dates?.published?.getTime() || 0) - (a.dates?.published?.getTime() || 0))

    const latest = posts[0]
    if (!latest) return null

    // Generate a safe relative link from the current page to the post
    const url = resolveRelative(fileData.slug!, latest.slug!)

    return (
      <div class="latest-post" style={{ margin: "1rem 0", fontWeight: "bold" }}>
        <span>latest post: <a href={url}>[Click to go]</a></span>
      </div>
    )
  }
  return LatestPost
}) satisfies QuartzComponentConstructor
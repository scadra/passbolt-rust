# Tags & Comments Module

## Overview

Tags and comments are secondary features that enhance resource organization and collaboration. Tags allow categorizing resources with labels, while comments enable discussion threads on individual resources.

## Tags

**Current JS references:**
- `controller/tag/tagUpdateController.js` - Update tags
- `controller/tag/tagDeleteController.js` - Delete tags
- `service/api/tag/tagService.js` - Tag API client
- `model/entity/tag/` - Tag entities
- `event/` for `passbolt.tags.*` events

### Tag Entity

```json
{
  "id": "<uuid>",
  "slug": "my-tag",
  "is_shared": true
}
```

### Tag Types

- **Personal tags**: Prefixed with `#`, visible only to the creator
- **Shared tags**: No prefix, visible to all users with access to the tagged resource

### Tag Slug Rules

Tag slugs (the tag name) must follow these validation rules:
- **Length**: 1 to 128 characters (UTF-8)
- **Allowed characters**: Alphanumeric, hyphens, underscores, spaces, and Unicode letters
- **Personal tag prefix**: `#` prefix is reserved for personal tags. If the slug starts with `#`, the tag is automatically personal
- **Uniqueness**: Slugs are unique per scope (personal tags: unique per user; shared tags: unique globally)
- **Case sensitivity**: Slugs are case-insensitive for uniqueness checks (stored as provided, compared lowercase)
- **Trimming**: Leading and trailing whitespace is trimmed

### Permissions

- **Personal tags** (`#`-prefixed): Only the creator can see, modify, or delete
- **Shared tags**: Visible to all users who have access to at least one resource tagged with it
- **Adding a shared tag**: Requires at least `Update` (7) permission on the resource
- **Removing a shared tag from a resource**: Requires at least `Update` (7) permission on the resource
- **Renaming a shared tag**: Requires admin role
- **Deleting a shared tag**: Requires admin role
- **Adding a personal tag**: Requires at least `Read` (1) permission on the resource

### Operations

#### Find All Tags
- `GET /tags.json`
- Returns all tags accessible to the current user
- **Note**: No dedicated autocomplete endpoint exists. Tag autocomplete is implemented client-side by filtering the local tag cache against user input

#### Add Tag to Resource
- `POST /tags/<resource_id>.json` with `{ slug: "tag-name" }`
- Creates the tag if it doesn't exist
- Creates the resource-tag association

#### Update Resource Tags
- `PUT /resources/<resource_id>/tags.json` with `{ tags: [...] }`
- Replaces all tags on a resource

#### Update Tag (Rename)
- `PUT /tags/<id>.json` with `{ slug: "new-name" }`

#### Delete Tag
- `DELETE /tags/<id>.json`
- Removes the tag and all its associations

## Comments

**Current JS references:**
- `controller/comment/commentCreateController.js` - Create comments
- `controller/comment/commentDeleteController.js` - Delete comments
- `service/api/comment/commentService.js` - Comment API client
- `model/entity/comment/` - Comment entities
- `event/commentEvents.js` - Comment event handlers

### Comment Entity

```json
{
  "id": "<uuid>",
  "parent_id": "<uuid|null>",
  "foreign_key": "<resource_uuid>",
  "foreign_model": "Resource",
  "content": "This is a comment",
  "created": "2024-01-01T00:00:00Z",
  "modified": "2024-01-01T00:00:00Z",
  "created_by": "<uuid>",
  "modified_by": "<uuid>",
  "creator": { /* user profile */ }
}
```

### Comment Threading

Comments support single-level threading via `parent_id`:
- **Top-level comments**: `parent_id` is `null`
- **Replies**: `parent_id` points to a top-level comment's ID
- **Nesting limit**: Only one level of nesting is supported (no replies to replies). If a `parent_id` references a comment that itself has a `parent_id`, the server rejects the request
- **Display order**: Comments are returned sorted by `created` ascending. Client should group replies under their parent for display

### Comment Validation

- **Content**: Required, 1 to 256 characters (UTF-8), must not be blank
- **parent_id**: Must reference an existing comment on the same resource, or be null
- **foreign_model**: Always `"Resource"` (only resource comments are supported)

### Permissions

- **Reading comments**: Requires at least `Read` (1) permission on the resource
- **Creating comments**: Requires at least `Read` (1) permission on the resource (any user with access can comment)
- **Deleting comments**: Only the comment creator or a user with admin role can delete
- **Editing comments**: Not supported. Users must delete and recreate

### Operations

#### Find Comments for Resource
- `GET /comments/resource/<resource_id>.json`
- Returns all comments on a resource, sorted by creation date ascending
- Contains: `creator` (user profile)
- Supports pagination via `PaginationParams` (declared in architecture, but note: the current JS implementation fetches all comments at once without pagination; the server supports it but it is not actively used)

#### Create Comment
- `POST /comments/resource/<resource_id>.json`
- Payload: `{ content: "Comment text", parent_id: null }`
- `parent_id` supports threaded replies (single level only)
- Returns the created comment with `creator` populated

#### Delete Comment
- `DELETE /comments/<id>.json`
- Only the comment creator or an admin can delete
- Deleting a parent comment does **not** cascade-delete its replies (replies become orphaned top-level comments)

## Proposed Rust API

```rust
pub struct TagsClient<T: Transport, S: Storage> {
    transport: Arc<T>,
    storage: Arc<S>,
}

impl<T: Transport, S: Storage> TagsClient<T, S> {
    /// Find all tags
    pub async fn find_all(&self) -> Result<Vec<Tag>, TagError>;

    /// Add a tag to a resource
    pub async fn add_to_resource(&self, resource_id: &Uuid, slug: &str) -> Result<Tag, TagError>;

    /// Update all tags on a resource
    pub async fn update_resource_tags(
        &self,
        resource_id: &Uuid,
        tags: &[String],
    ) -> Result<Vec<Tag>, TagError>;

    /// Update a tag (rename)
    pub async fn update(&self, id: &Uuid, slug: &str) -> Result<Tag, TagError>;

    /// Delete a tag
    pub async fn delete(&self, id: &Uuid) -> Result<(), TagError>;
}

pub struct CommentsClient<T: Transport, S: Storage> {
    transport: Arc<T>,
    storage: Arc<S>,
}

impl<T: Transport, S: Storage> CommentsClient<T, S> {
    /// Find all comments for a resource
    pub async fn find_all_by_resource(
        &self,
        resource_id: &Uuid,
    ) -> Result<Vec<Comment>, CommentError>;

    /// Create a comment on a resource
    pub async fn create(
        &self,
        resource_id: &Uuid,
        content: &str,
        parent_id: Option<Uuid>,
    ) -> Result<Comment, CommentError>;

    /// Delete a comment
    pub async fn delete(&self, id: &Uuid) -> Result<(), CommentError>;
}

// --- Data Types ---

pub struct Tag {
    pub id: Uuid,
    pub slug: String,
    pub is_shared: bool,
    pub created: DateTime<Utc>,
    pub modified: DateTime<Utc>,
}

pub struct Comment {
    pub id: Uuid,
    pub parent_id: Option<Uuid>,
    pub foreign_key: Uuid,       // resource ID
    pub foreign_model: String,   // "Resource"
    pub content: String,
    pub created: DateTime<Utc>,
    pub modified: DateTime<Utc>,
    pub created_by: Uuid,
    pub modified_by: Uuid,
    pub creator: Option<UserProfile>,
    pub children: Option<Vec<Comment>>,  // populated client-side for threaded display
}
```

## Error Types

```rust
#[derive(Error, Debug)]
pub enum TagError {
    #[error("Tag not found: {id}")]
    NotFound { id: Uuid },
    #[error("Validation failed: {0}")]
    ValidationFailed(String),
    #[error("Tag slug already exists: {slug}")]
    DuplicateSlug { slug: String },
    #[error("Insufficient permissions")]
    InsufficientPermissions,
    #[error(transparent)]
    Transport(#[from] TransportError),
}

#[derive(Error, Debug)]
pub enum CommentError {
    #[error("Comment not found: {id}")]
    NotFound { id: Uuid },
    #[error("Validation failed: {0}")]
    ValidationFailed(String),
    #[error("Cannot delete: insufficient permissions")]
    InsufficientPermissions,
    #[error(transparent)]
    Transport(#[from] TransportError),
}
```

CREATE TABLE backlinks (
    uri TEXT NOT NULL,
    path TEXT NOT NULL,
    link_to TEXT NOT NULL,
    repo_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (uri, path)
);

CREATE INDEX backlinks_path_link_to_idx ON backlinks(path, link_to);
CREATE INDEX backlinks_repo_id_idx ON backlinks(repo_id);

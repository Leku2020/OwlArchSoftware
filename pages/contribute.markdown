---
layout: contribute
title: Contribute
permalink: /contribute
---

[🔙 Go back home](/OwlArchSoftware/)

# Contributing to OwlArchSoftware

Thank you for contributing to OwlArchSoftware! This guide helps you contribute to the development of custom tools and software designed to complement the OwlArch Linux distribution. Follow these steps to ensure smooth integration of your changes.

---

## Repository Structure  
```  
.
├── objective/             # Source code for custom tools
│   ├── tool1/             # Example tool 1
│   ├── tool2/             # Example tool 2
│   └── ...                # Additional tools
├── pages/                 # Documentation for tools
└── .github/               # Helper scripts for building and testing
```

---

## Adding/Updating Tools  

### 1. **Adding New Tools**  
1. Create a new directory under `objective/` for your tool.  
   ```bash
   mkdir objective/my-new-tool
   ```
2. Add your tool's source code and a `README.md` file explaining its purpose and usage.  
3. Update the `pages/` directory with relevant documentation for your tool.  

### 2. **Customizing Existing Tools**  
- Modify the source code in the respective `objective/` directory.  
- Update the documentation in `pages/` to reflect the changes.  

---

## Branching & Pull Requests  

### Branch Strategy  
- `main`: Stable production-ready tools  
- `feature/*`: Experimental changes (automatically tested)  

### PR Requirements  
- [ ] Code is properly documented  
- [ ] Tests are included for new functionality  
- [ ] Documentation is updated in `pages/`  
- [ ] Code is linted and passes all checks  

---

### Manual Testing  
- Run the tool locally and verify its functionality.  
- Ensure compatibility with the OwlArch Linux distribution.  

---

## Common Issues  

### Build Failures  
- **Missing Dependencies**: Ensure all required libraries are installed.  
- **Code Errors**: Check the logs for syntax or runtime errors.  

---

## Deployment Process  

### For Pages:

On `main` branch push:  
1. Updates documentation at [OwlArchSoftware Docs](https://leku2020.github.io/OwlArchSoftware).  

---

## Getting Help  

- **Build Logs**: [GitHub Actions](https://github.com/Leku2020/OwlArchSoftware/actions)
- **Examples**:  
  - [Tool Integration](https://github.com/Leku2020/OwlArchSoftware/tree/main)  
  - [Documentation](https://github.com/Leku2020/OwlArchSoftware/tree/main/pages)  

Help us keep OwlArchSoftware innovative and effective for malware analysis and OSINT operations! 🦉🔍